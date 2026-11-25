package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

// UpstreamSocksConfig holds parsed upstream SOCKS5 proxy configuration
type UpstreamSocksConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

// Address returns host:port for dialing
func (c *UpstreamSocksConfig) Address() string {
	return net.JoinHostPort(c.Host, c.Port)
}

// HasAuth returns true if authentication credentials are present
func (c *UpstreamSocksConfig) HasAuth() bool {
	return c.Username != ""
}

// parseUpstreamSocksURL parses a SOCKS proxy URL with optional authentication.
// Supports formats:
//   - host:port
//   - socks://host:port
//   - socks5://host:port
//   - socks5h://host:port
//   - socks5://user:pass@host:port
func parseUpstreamSocksURL(s string) (*UpstreamSocksConfig, error) {
	config := &UpstreamSocksConfig{}

	// Strip known prefixes
	s = strings.TrimPrefix(s, "socks://")
	s = strings.TrimPrefix(s, "socks5://")
	s = strings.TrimPrefix(s, "socks5h://")

	// Try parsing as URL to extract user info
	if strings.Contains(s, "@") {
		u, err := url.Parse("socks5://" + s)
		if err != nil {
			return nil, fmt.Errorf("invalid SOCKS URL: %w", err)
		}
		if u.User != nil {
			config.Username = u.User.Username()
			config.Password, _ = u.User.Password()
		}
		config.Host = u.Hostname()
		config.Port = u.Port()
		if config.Port == "" {
			config.Port = "1080"
		}
		return config, nil
	}

	// Simple host:port format
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Maybe just host without port
		config.Host = s
		config.Port = "1080"
		return config, nil
	}
	config.Host = host
	config.Port = port
	return config, nil
}

// SpawnRoutine spawns a SOCKS5 tunnel that chains through upstream SOCKS5
func (config *Socks5TunnelConfig) SpawnRoutine(vt *VirtualTun) {
	upstream, err := parseUpstreamSocksURL(config.Target)
	if err != nil {
		log.Fatalf("Invalid Socks5Tunnel target %s: %v", config.Target, err)
	}

	// Local authentication
	var authMethods []socks5.Authenticator
	if config.Username != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{config.Username: config.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	// Extract bind IP for UDP
	bindHost, _, err := net.SplitHostPort(config.BindAddress)
	if err != nil {
		log.Fatalf("Invalid Socks5Tunnel bind address %s: %v", config.BindAddress, err)
	}
	bindIP := net.ParseIP(bindHost)

	options := []socks5.Option{
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
		socks5.WithResolver(vt),
		socks5.WithLogger(socks5.NewLogger(errorLogger)),
		// Custom handlers for chaining
		socks5.WithConnectHandle(makeChainedConnectHandler(vt, upstream)),
		socks5.WithAssociateHandle(makeChainedAssociateHandler(vt, upstream, bindIP)),
	}

	server := socks5.NewServer(options...)

	log.Printf("Socks5Tunnel listening on %s -> %s\n", config.BindAddress, upstream.Address())
	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Fatal(err)
	}
}

// upstreamHandshakeTimeout bounds the blocking reads performed while
// negotiating with the upstream SOCKS server. vt.Tnet.DialContext already
// bounds the connect attempt via ctx, but the reads after a successful connect
// are not covered by ctx, so a wedged upstream that never replies would
// otherwise block the handler goroutine (and leak its netstack conn) forever.
const upstreamHandshakeTimeout = 10 * time.Second

// makeChainedConnectHandler creates a TCP CONNECT handler that chains through upstream
func makeChainedConnectHandler(vt *VirtualTun, upstream *UpstreamSocksConfig) func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	return func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		target := request.DestAddr.String()

		// Connect to upstream SOCKS5 via WireGuard
		upstreamConn, err := vt.Tnet.DialContext(ctx, "tcp", upstream.Address())
		if err != nil {
			_ = socks5.SendReply(writer, statute.RepHostUnreachable, nil)
			return fmt.Errorf("failed to connect to upstream: %w", err)
		}
		defer func() { _ = upstreamConn.Close() }()

		// Bound the handshake reads; ctx only covers the dial, not the reads
		// that follow a successful connect.
		_ = upstreamConn.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))

		// Perform SOCKS5 handshake with upstream
		if err := upstreamHandshake(upstreamConn, upstream); err != nil {
			_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
			return fmt.Errorf("upstream handshake failed: %w", err)
		}

		// Send CONNECT request to upstream
		if err := upstreamConnect(upstreamConn, target); err != nil {
			_ = socks5.SendReply(writer, statute.RepHostUnreachable, nil)
			return fmt.Errorf("upstream connect failed: %w", err)
		}

		// Handshake done; drop the deadline before the unbounded proxy copy.
		_ = upstreamConn.SetDeadline(time.Time{})

		// Success - tell client we're connected
		if err := socks5.SendReply(writer, statute.RepSuccess, upstreamConn.LocalAddr()); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}

		// Proxy data bidirectionally. Propagate half-close so a client that
		// finishes its request and shuts down its send side signals EOF to the
		// upstream instead of tearing the connection down, and wait for BOTH
		// directions before the deferred Close runs so the upstream's response
		// is not truncated mid-flight.
		copyDone := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(upstreamConn, request.Reader)
			if cw, ok := upstreamConn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			copyDone <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(writer, upstreamConn)
			if cw, ok := writer.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			copyDone <- struct{}{}
		}()

		<-copyDone
		<-copyDone
		return nil
	}
}

// makeChainedAssociateHandler creates a UDP ASSOCIATE handler that chains through upstream
func makeChainedAssociateHandler(vt *VirtualTun, upstream *UpstreamSocksConfig, bindIP net.IP) func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	return func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		// Connect to upstream SOCKS5 via WireGuard
		upstreamCtrl, err := vt.Tnet.DialContext(ctx, "tcp", upstream.Address())
		if err != nil {
			_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
			return fmt.Errorf("failed to connect to upstream: %w", err)
		}
		defer func() { _ = upstreamCtrl.Close() }()

		// Bound the handshake reads; ctx only covers the dial, not the reads
		// that follow a successful connect.
		_ = upstreamCtrl.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))

		// Perform SOCKS5 handshake with upstream
		if err := upstreamHandshake(upstreamCtrl, upstream); err != nil {
			_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
			return fmt.Errorf("upstream handshake failed: %w", err)
		}

		// Request UDP ASSOCIATE from upstream
		relayHost, relayPort, err := upstreamUDPAssociate(upstreamCtrl, upstream)
		if err != nil {
			_ = socks5.SendReply(writer, statute.RepCommandNotSupported, nil)
			return fmt.Errorf("upstream UDP associate failed: %w", err)
		}

		// Association established; the control connection now lives for the
		// association's lifetime (watched below), so drop the handshake
		// deadline before the long-lived read.
		_ = upstreamCtrl.SetDeadline(time.Time{})

		// Connect to upstream's UDP relay via WireGuard
		upstreamRelayAddr := net.JoinHostPort(relayHost, strconv.Itoa(relayPort))
		upstreamUDP, err := vt.Tnet.DialContext(ctx, "udp", upstreamRelayAddr)
		if err != nil {
			_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
			return fmt.Errorf("failed to connect to upstream UDP relay: %w", err)
		}
		defer func() { _ = upstreamUDP.Close() }()

		// Create local UDP listener for the client, bound to the IP the
		// control connection arrived on so the BND.ADDR reply is usable even
		// when BindAddress is a wildcard or hostname
		relayIP := bindIP
		if tcpAddr, ok := request.LocalAddr.(*net.TCPAddr); ok {
			relayIP = tcpAddr.IP
		}
		localUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: relayIP, Port: 0})
		if err != nil {
			_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
			return fmt.Errorf("failed to create local UDP listener: %w", err)
		}
		defer func() { _ = localUDP.Close() }()

		// Tell client our local UDP address
		if err := socks5.SendReply(writer, statute.RepSuccess, localUDP.LocalAddr()); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}

		// Only accept datagrams from the IP that opened the association, so
		// another host cannot inject packets or hijack the reply path
		var expectedClient netip.Addr
		if tcpAddr, ok := request.RemoteAddr.(*net.TCPAddr); ok {
			expectedClient = tcpAddr.AddrPort().Addr().Unmap()
		}

		// Track client address for sending responses
		var clientAddr netip.AddrPort
		var clientAddrMu sync.RWMutex

		// Relay: client -> upstream
		go func() {
			buf := make([]byte, 65535)
			for {
				n, addr, err := localUDP.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				// A SOCKS5 UDP datagram header is at least 10 bytes (2 RSV +
				// 1 FRAG + 1 ATYP + 4 IPv4 + 2 port). RFC 1928 also requires
				// dropping fragmented datagrams (FRAG != 0) when reassembly is
				// unsupported, which it is here and in the upstream relay.
				if n < 10 || buf[2] != 0x00 {
					continue
				}
				if expectedClient.IsValid() && addr.Addr().Unmap() != expectedClient {
					continue
				}
				clientAddrMu.Lock()
				clientAddr = addr
				clientAddrMu.Unlock()

				// Forward to upstream (already SOCKS5 framed from client)
				_, _ = upstreamUDP.Write(buf[:n])
			}
		}()

		// Relay: upstream -> client
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := upstreamUDP.Read(buf)
				if err != nil {
					return
				}

				clientAddrMu.RLock()
				addr := clientAddr
				clientAddrMu.RUnlock()

				if addr.IsValid() {
					_, _ = localUDP.WriteToUDPAddrPort(buf[:n], addr)
				}
			}
		}()

		// The association lives until either control connection closes.
		// RFC 1928 lets either side tear it down: the downstream client by
		// closing its control connection, or the upstream relay by closing
		// ours. Watch both; whichever ends first tears everything down via the
		// deferred closes above, which unblock both relay goroutines.
		done := make(chan struct{})
		var once sync.Once
		finish := func() { once.Do(func() { close(done) }) }

		// Watch the upstream control connection for teardown.
		go func() {
			defer finish()
			buf := make([]byte, 1)
			for {
				if _, err := upstreamCtrl.Read(buf); err != nil {
					return
				}
			}
		}()

		// Watch the downstream client control connection.
		go func() {
			defer finish()
			buf := make([]byte, 1)
			for {
				if _, err := request.Reader.Read(buf); err != nil {
					return
				}
			}
		}()

		<-done
		return nil
	}
}

// upstreamHandshake performs SOCKS5 handshake with upstream
func upstreamHandshake(conn net.Conn, config *UpstreamSocksConfig) error {
	// Send greeting
	greeting := []byte{0x05, 0x01, 0x00}
	if config.HasAuth() {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("invalid SOCKS version")
	}

	switch resp[1] {
	case 0x00:
		// No auth
	case 0x02:
		// Username/password auth
		if !config.HasAuth() {
			return errors.New("server requires auth")
		}
		authReq := []byte{0x01, byte(len(config.Username))}
		authReq = append(authReq, []byte(config.Username)...)
		authReq = append(authReq, byte(len(config.Password)))
		authReq = append(authReq, []byte(config.Password)...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return errors.New("auth failed")
		}
	case 0xFF:
		return errors.New("no acceptable auth method")
	default:
		return fmt.Errorf("unsupported auth method: %d", resp[1])
	}

	return nil
}

// upstreamConnect sends CONNECT request to upstream
func upstreamConnect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	// Build CONNECT request
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read response header
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return err
	}
	if respHdr[1] != 0x00 {
		return fmt.Errorf("connect rejected: %d", respHdr[1])
	}

	// Consume BND.ADDR
	var addrLen int
	switch respHdr[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	}
	discard := make([]byte, addrLen+2)
	_, err = io.ReadFull(conn, discard)
	return err
}

// upstreamUDPAssociate requests UDP ASSOCIATE from upstream
func upstreamUDPAssociate(conn net.Conn, config *UpstreamSocksConfig) (string, int, error) {
	// Send UDP ASSOCIATE request
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return "", 0, err
	}

	// Read response header
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return "", 0, err
	}
	if respHdr[1] != 0x00 {
		return "", 0, fmt.Errorf("UDP associate rejected: %d", respHdr[1])
	}

	// Parse BND.ADDR
	var relayHost string
	switch respHdr[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		relayHost = net.IP(addr).String()
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		relayHost = net.IP(addr).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		relayHost = string(domain)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])

	// A wildcard or loopback BND.ADDR is not reachable through the tunnel;
	// use the upstream server's address instead
	if ip := net.ParseIP(relayHost); ip != nil && (ip.IsUnspecified() || ip.IsLoopback()) {
		relayHost = config.Host
	}

	return relayHost, relayPort, nil
}
