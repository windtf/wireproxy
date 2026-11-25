package wireproxy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// In-process end-to-end tests for the two SOCKS UDP ASSOCIATE paths. Two
// WireGuard netstack instances (peer A and peer B) are peered over a localhost
// UDP socket using the real StartWireguard construction path. A UDP echo
// service lives inside peer B's netstack, reachable from peer A only through
// the tunnel, so the tests exercise the exact netstack dialer path the relays
// use in production.
//
// Each peer gets a fresh Curve25519 keypair per test run (see genKeypair).
const (
	e2eAAddr = "10.0.0.1"
	e2eBAddr = "10.0.0.2"
)

// genKeypair returns a fresh WireGuard keypair as hex strings, the form the
// config loader stores keys in after base64 decoding.
func genKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key.Bytes()), hex.EncodeToString(key.PublicKey().Bytes())
}

// freeTCPPort returns a currently-free localhost TCP port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// freeUDPPort returns a currently-free localhost UDP port (for a WG bind).
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startPeers brings up two WireGuard netstack peers over localhost and returns
// them handshaked and ready.
func startPeers(t *testing.T) (vtA, vtB *VirtualTun) {
	t.Helper()
	portA := freeUDPPort(t)
	portB := freeUDPPort(t)
	aPriv, aPub := genKeypair(t)
	bPriv, bPub := genKeypair(t)

	mk := func(priv, addr string, listenPort int, peerPub string, peerPort int, peerAllowed string) *Configuration {
		lp := listenPort
		ep := fmt.Sprintf("127.0.0.1:%d", peerPort)
		return &Configuration{
			Device: &DeviceConfig{
				SecretKey:  priv,
				Endpoint:   []netip.Addr{netip.MustParseAddr(addr)},
				ListenPort: &lp,
				MTU:        1420,
				Peers: []PeerConfig{{
					PublicKey:    peerPub,
					PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
					Endpoint:     &ep,
					KeepAlive:    5,
					AllowedIPs:   []netip.Prefix{netip.MustParsePrefix(peerAllowed)},
				}},
			},
			Resolve: &ResolveConfig{ResolveStrategy: "ipv4"},
		}
	}

	var err error
	vtA, err = StartWireguard(mk(aPriv, e2eAAddr, portA, bPub, portB, e2eBAddr+"/32"), 0)
	if err != nil {
		t.Fatalf("start peer A: %v", err)
	}
	t.Cleanup(func() { vtA.Dev.Close() })

	vtB, err = StartWireguard(mk(bPriv, e2eBAddr, portB, aPub, portA, e2eAAddr+"/32"), 0)
	if err != nil {
		t.Fatalf("start peer B: %v", err)
	}
	t.Cleanup(func() { vtB.Dev.Close() })

	warmup(t, vtA, vtB)
	return vtA, vtB
}

// warmup forces the WireGuard handshake to complete synchronously by driving a
// TCP round trip A->B, so tests don't pay handshake latency on their first
// (unretransmitted) UDP datagram.
func warmup(t *testing.T, vtA, vtB *VirtualTun) {
	t.Helper()
	ln, err := vtB.Tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(e2eBAddr), Port: 9})
	if err != nil {
		t.Fatalf("warmup listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	deadline := time.Now().Add(15 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := vtA.Tnet.DialContext(ctx, "tcp", net.JoinHostPort(e2eBAddr, "9"))
		cancel()
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, werr := c.Write([]byte("x"))
			b := make([]byte, 1)
			_, rerr := io.ReadFull(c, b)
			_ = c.Close()
			if werr == nil && rerr == nil {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("warmup handshake did not complete: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// socksNegotiate performs SOCKS5 method negotiation, optionally with
// username/password auth (RFC 1929).
func socksNegotiate(conn net.Conn, user, pass string) error {
	if user == "" {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			return err
		}
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("bad version %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return err
		}
		if ar[1] != 0x00 {
			return errors.New("auth rejected")
		}
		return nil
	case 0xFF:
		return errors.New("no acceptable auth method")
	default:
		return fmt.Errorf("unexpected method %d", resp[1])
	}
}

// socksUDPAssociate issues UDP ASSOCIATE (DST 0.0.0.0:0) and parses the relay
// address from the reply.
func socksUDPAssociate(conn net.Conn) (netip.AddrPort, error) {
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return netip.AddrPort{}, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return netip.AddrPort{}, err
	}
	if hdr[1] != 0x00 {
		return netip.AddrPort{}, fmt.Errorf("associate rejected: %d", hdr[1])
	}
	var raw []byte
	switch hdr[3] {
	case 0x01:
		raw = make([]byte, 4)
	case 0x04:
		raw = make([]byte, 16)
	default:
		return netip.AddrPort{}, fmt.Errorf("unexpected atyp %d", hdr[3])
	}
	if _, err := io.ReadFull(conn, raw); err != nil {
		return netip.AddrPort{}, err
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad BND.ADDR %v", raw)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(pb)), nil
}

// wrapUDP frames a payload in a SOCKS5 UDP datagram for an IPv4 destination.
func wrapUDP(dst netip.AddrPort, payload []byte) []byte {
	b := []byte{0x00, 0x00, 0x00, 0x01}
	a4 := dst.Addr().As4()
	b = append(b, a4[:]...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], dst.Port())
	b = append(b, p[:]...)
	return append(b, payload...)
}

// unwrapUDP strips a SOCKS5 UDP datagram header and returns the payload.
func unwrapUDP(b []byte) ([]byte, error) {
	if len(b) < 10 {
		return nil, errors.New("short datagram")
	}
	switch b[3] {
	case 0x01:
		return b[10:], nil
	case 0x04:
		if len(b) < 22 {
			return nil, errors.New("short IPv6 datagram")
		}
		return b[22:], nil
	case 0x03:
		hl := 5 + int(b[4]) + 2
		if len(b) < hl {
			return nil, errors.New("short domain datagram")
		}
		return b[hl:], nil
	}
	return nil, fmt.Errorf("unexpected atyp %d", b[3])
}

// udpEchoRoundtrip sends datagram and asserts the echoed payload, retrying the
// whole exchange since UDP has no retransmit.
func udpEchoRoundtrip(t *testing.T, uc net.Conn, datagram []byte, want string) {
	t.Helper()
	buf := make([]byte, 2048)
	deadline := time.Now().Add(8 * time.Second)
	for {
		_ = uc.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := uc.Write(datagram); err != nil {
			t.Fatalf("udp write: %v", err)
		}
		_ = uc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := uc.Read(buf)
		if err == nil {
			payload, perr := unwrapUDP(buf[:n])
			if perr != nil {
				t.Fatalf("unwrap reply: %v", perr)
			}
			if string(payload) != want {
				t.Fatalf("echo payload = %q, want %q", payload, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no echo after retries: %v", err)
		}
	}
}

// drainUDP discards any datagrams already buffered on uc (e.g. a duplicate
// echo left by a retried round trip) so a later expectNoEcho is not confused.
func drainUDP(uc net.Conn) {
	buf := make([]byte, 2048)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := uc.Read(buf); err != nil {
			return
		}
	}
}

// expectNoEcho sends datagram once and asserts nothing comes back (dropped).
func expectNoEcho(t *testing.T, uc net.Conn, datagram []byte) {
	t.Helper()
	_ = uc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := uc.Write(datagram); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 2048)
	if n, err := uc.Read(buf); err == nil {
		t.Fatalf("expected datagram to be dropped, got %d bytes back", n)
	}
}

// waitTCPListening blocks until a TCP listener accepts connections at addr.
func waitTCPListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never came up at %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startNetstackUDPEcho runs a UDP echo server inside vt's netstack.
func startNetstackUDPEcho(t *testing.T, vt *VirtualTun, ip string, port int) {
	t.Helper()
	uc, err := vt.Tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := uc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteTo(buf[:n], raddr)
		}
	}()
}

// upstreamSOCKS is a minimal SOCKS5 UDP relay bound entirely inside a peer's
// netstack, standing in for the upstream server that [Socks5Tunnel] chains
// through. It echoes SOCKS5 UDP datagrams back to the sender (correct because
// [Socks5Tunnel] forwards both directions unparsed) and exposes teardown
// observables.
type upstreamSOCKS struct {
	ln         net.Listener
	ip         string
	associated chan net.Conn // control conns, published once the association is up
	ctrlEOF    chan struct{} // fires when an accepted control conn's read returns
}

func startUpstreamSOCKS(t *testing.T, vt *VirtualTun, ip string, port int) *upstreamSOCKS {
	t.Helper()
	ln, err := vt.Tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &upstreamSOCKS{
		ln:         ln,
		ip:         ip,
		associated: make(chan net.Conn, 4),
		ctrlEOF:    make(chan struct{}, 4),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.handle(vt, c)
		}
	}()
	return u
}

func (u *upstreamSOCKS) handle(vt *VirtualTun, c net.Conn) {
	defer c.Close()

	// Method negotiation (accept no-auth only).
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(greet[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Command request + DST address.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01:
		_, _ = io.ReadFull(c, make([]byte, 4+2))
	case 0x04:
		_, _ = io.ReadFull(c, make([]byte, 16+2))
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		_, _ = io.ReadFull(c, make([]byte, int(lb[0])+2))
	}
	if req[1] != 0x03 { // only UDP ASSOCIATE is expected
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Open a netstack UDP relay and advertise its concrete address.
	relay, err := vt.Tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP(u.ip), Port: 0})
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()
	_, portStr, _ := net.SplitHostPort(relay.LocalAddr().String())
	relayPort, _ := strconv.Atoi(portStr)

	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, net.ParseIP(u.ip).To4()...)
	reply = append(reply, byte(relayPort>>8), byte(relayPort))
	if _, err := c.Write(reply); err != nil {
		return
	}

	// Echo SOCKS5 UDP datagrams back to their sender.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = relay.WriteTo(buf[:n], raddr)
		}
	}()

	select {
	case u.associated <- c:
	default:
	}

	// Hold the control connection open; signal when it ends.
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			select {
			case u.ctrlEOF <- struct{}{}:
			default:
			}
			return
		}
	}
}

// TestSocks5UDPEchoThroughTunnel drives a real SOCKS5 UDP ASSOCIATE client
// against [Socks5] on peer A and asserts the echo round-trips through the
// tunnel, and that the relay reply advertises a concrete BND.ADDR.
func TestSocks5UDPEchoThroughTunnel(t *testing.T) {
	vtA, vtB := startPeers(t)
	startNetstackUDPEcho(t, vtB, e2eBAddr, 5000)

	bind := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	go (&Socks5Config{BindAddress: bind}).SpawnRoutine(vtA)
	waitTCPListening(t, bind)

	ctrl, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := socksNegotiate(ctrl, "", ""); err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	relay, err := socksUDPAssociate(ctrl)
	if err != nil {
		t.Fatalf("associate: %v", err)
	}
	if relay.Addr().IsUnspecified() {
		t.Fatalf("BND.ADDR is a wildcard, not reachable: %v", relay)
	}

	uc, err := net.Dial("udp", relay.String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	dst := netip.AddrPortFrom(netip.MustParseAddr(e2eBAddr), 5000)
	udpEchoRoundtrip(t, uc, wrapUDP(dst, []byte("hello tunnel")), "hello tunnel")
}

// TestSocks5AuthAcceptReject checks username/password auth on [Socks5].
func TestSocks5AuthAcceptReject(t *testing.T) {
	vtA, _ := startPeers(t)

	bind := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	go (&Socks5Config{BindAddress: bind, Username: "user", Password: "pass"}).SpawnRoutine(vtA)
	waitTCPListening(t, bind)

	good, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	if err := socksNegotiate(good, "user", "pass"); err != nil {
		t.Fatalf("correct credentials rejected: %v", err)
	}

	bad, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := socksNegotiate(bad, "user", "wrong"); err == nil {
		t.Fatal("wrong credentials were accepted")
	}
}

// TestSocks5TunnelUDPEcho drives the full [Socks5Tunnel] chain: client -> local
// chained server on peer A -> upstream SOCKS relay inside peer B's netstack. It
// asserts a successful echo, then that datagrams from an unexpected source IP
// and malformed/fragmented datagrams are dropped.
func TestSocks5TunnelUDPEcho(t *testing.T) {
	vtA, vtB := startPeers(t)
	startUpstreamSOCKS(t, vtB, e2eBAddr, 1080)

	bind := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	target := net.JoinHostPort(e2eBAddr, "1080")
	go (&Socks5TunnelConfig{BindAddress: bind, Target: target}).SpawnRoutine(vtA)
	waitTCPListening(t, bind)

	ctrl, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := socksNegotiate(ctrl, "", ""); err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	relay, err := socksUDPAssociate(ctrl)
	if err != nil {
		t.Fatalf("associate: %v", err)
	}
	if relay.Addr().IsUnspecified() {
		t.Fatalf("BND.ADDR is a wildcard, not reachable: %v", relay)
	}

	dst := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.33"), 9999)
	relayUDP := net.UDPAddrFromAddrPort(relay)

	// Positive: echo from the associated source IP.
	uc, err := net.Dial("udp", relay.String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	udpEchoRoundtrip(t, uc, wrapUDP(dst, []byte("ping chain")), "ping chain")
	drainUDP(uc) // discard any duplicate echo from a retried round trip

	// A3: too-short and fragmented datagrams are dropped locally.
	expectNoEcho(t, uc, []byte{0x00, 0x00, 0x00}) // < 10 bytes
	frag := wrapUDP(dst, []byte("frag"))
	frag[2] = 0x01 // FRAG != 0
	expectNoEcho(t, uc, frag)

	// Source filter: a datagram from a different loopback IP is dropped.
	badSrc, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, relayUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer badSrc.Close()
	expectNoEcho(t, badSrc, wrapUDP(dst, []byte("spoofed")))
}

// TestSocks5TunnelDownstreamTeardown asserts that closing the client control
// connection tears the whole chain down: the upstream control connection ends.
func TestSocks5TunnelDownstreamTeardown(t *testing.T) {
	vtA, vtB := startPeers(t)
	up := startUpstreamSOCKS(t, vtB, e2eBAddr, 1080)

	bind := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	go (&Socks5TunnelConfig{BindAddress: bind, Target: net.JoinHostPort(e2eBAddr, "1080")}).SpawnRoutine(vtA)
	waitTCPListening(t, bind)

	ctrl, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	if err := socksNegotiate(ctrl, "", ""); err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if _, err := socksUDPAssociate(ctrl); err != nil {
		t.Fatalf("associate: %v", err)
	}

	// Client hangs up its control connection.
	_ = ctrl.Close()

	select {
	case <-up.ctrlEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream control connection was not torn down after client closed")
	}
}

// TestSocks5TunnelUpstreamTeardown asserts that when the upstream closes its
// control connection (A2), the chain tears down and the client's control
// connection is closed.
func TestSocks5TunnelUpstreamTeardown(t *testing.T) {
	vtA, vtB := startPeers(t)
	up := startUpstreamSOCKS(t, vtB, e2eBAddr, 1080)

	bind := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	go (&Socks5TunnelConfig{BindAddress: bind, Target: net.JoinHostPort(e2eBAddr, "1080")}).SpawnRoutine(vtA)
	waitTCPListening(t, bind)

	ctrl, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := socksNegotiate(ctrl, "", ""); err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if _, err := socksUDPAssociate(ctrl); err != nil {
		t.Fatalf("associate: %v", err)
	}

	// Upstream relay closes the control connection it accepted.
	var upstreamCtrl net.Conn
	select {
	case upstreamCtrl = <-up.associated:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw the association")
	}
	_ = upstreamCtrl.Close()

	// The chained handler should return, causing the library to close the
	// client control connection. A prompt non-timeout error (EOF / reset /
	// closed) means teardown propagated; a read-deadline timeout means the
	// connection is still open, i.e. A2 did not fire.
	_ = ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = ctrl.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("client control connection stayed open after upstream teardown")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("upstream teardown did not close the client control connection (read timed out)")
	}
}
