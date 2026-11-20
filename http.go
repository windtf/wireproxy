package wireproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

// httpReadRequestTimeout bounds how long a client may take to send its request
// line and headers.
var httpReadRequestTimeout = 30 * time.Second

type HTTPServer struct {
	config *HTTPConfig

	auth CredentialValidator
	dial func(network, address string) (net.Conn, error)

	authRequired bool
	tlsRequired  bool
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf("%s", http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

// hopByHopHeaders are the headers that apply to a single transport-level
// connection (RFC 7230 section 6.1) plus the proxy-specific ones, and must not
// be forwarded to the origin.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	proxyAuthHeaderKey,
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders deletes the hop-by-hop headers, including any header
// named in a Connection header, so that proxy credentials and connection
// management do not leak to the origin.
func removeHopByHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		peer = nil
	}

	return
}

// isUpgrade returns the requested protocol if the client asked for a protocol
// upgrade (e.g. WebSocket) with both Connection: upgrade and an Upgrade header.
func isUpgrade(h http.Header) string {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return h.Get("Upgrade")
			}
		}
	}
	return ""
}

// writeInterim writes a 1xx response (100 Continue, 101 Switching Protocols)
// to the client.
func writeInterim(w io.Writer, resp *http.Response) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %s\r\n", resp.Status); err != nil {
		return err
	}
	if err := resp.Header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// handle forwards one plain-HTTP request to the origin on its own connection
// and relays the response. rd holds any bytes of the client connection that
// were read ahead of the request.
func (s *HTTPServer) handle(req *http.Request, conn net.Conn, rd io.Reader) error {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err := s.dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("tun tcp dial failed: %w", err)
	}
	defer func() { _ = peer.Close() }()

	upgrade := isUpgrade(req.Header)
	removeHopByHopHeaders(req.Header)
	if upgrade != "" {
		// Keep the upgrade handshake (e.g. WebSocket) so it can be tunnelled.
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", upgrade)
	} else {
		// One origin connection per request: ask the origin to close after
		// the response.
		req.Close = true
	}

	// An origin that goes silent must not hold the connection forever.
	d := proxyIdleTimeout
	idle := time.AfterFunc(d, func() { _ = peer.Close() })
	defer idle.Stop()
	oc := idleConn{Conn: peer, reset: func() { idle.Reset(d) }}

	// Write the request while relaying the response, so that an interim
	// response (100 Continue) reaches a client that is waiting for it before it
	// sends the body.
	written := make(chan error, 1)
	go func() {
		err := req.Write(oc)
		if err != nil {
			_ = peer.Close()
		}
		written <- err
	}()

	br := bufio.NewReader(oc)
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			// Do not wait for the writer: it may be blocked reading a
			// request body the client has not sent. serve closes the client
			// connection, which unblocks it.
			select {
			case werr := <-written:
				if werr != nil {
					return fmt.Errorf("conn write failed: %w", werr)
				}
			default:
			}
			return fmt.Errorf("read response failed: %w", err)
		}

		if resp.StatusCode == http.StatusSwitchingProtocols && upgrade != "" {
			if err := writeInterim(conn, resp); err != nil {
				return err
			}
			if err := <-written; err != nil {
				return fmt.Errorf("conn write failed: %w", err)
			}
			idle.Stop()
			// Tunnel from here on. The origin's reads are no longer
			// idle-tracked, and br may hold bytes sent right after the 101.
			buffered, _ := br.Peek(br.Buffered())
			ahead := append([]byte(nil), buffered...)
			proxyCopy(readerConn{Conn: conn, r: rd}, readerConn{Conn: peer, r: io.MultiReader(bytes.NewReader(ahead), peer)})
			return nil
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			if err := writeInterim(conn, resp); err != nil {
				return err
			}
			continue
		}

		resp.Close = true
		err = resp.Write(conn)
		_ = resp.Body.Close()
		return err
	}
}

func (s *HTTPServer) serve(conn net.Conn) {
	var handled bool
	defer func() {
		if !handled {
			_ = conn.Close()
		}
	}()
	if err := conn.SetReadDeadline(time.Now().Add(httpReadRequestTimeout)); err != nil {
		log.Printf("set read deadline failed: %s\n", err)
		return
	}
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		log.Printf("read request failed: %s\n", err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("clear read deadline failed: %s\n", err)
		return
	}

	code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		log.Println(err)
		return
	}

	if req.Method != http.MethodConnect {
		if err := s.handle(req, conn, rd); err != nil {
			log.Printf("proxy request failed: %s\n", err)
		}
		return
	}

	peer, err := s.handleConn(req, conn)
	if err != nil {
		if peer != nil {
			_ = peer.Close()
		}
		log.Printf("dial proxy failed: %s\n", err)
		return
	}
	if peer == nil {
		log.Println("dial proxy failed: peer nil")
		return
	}

	handled = true

	// rd may already hold bytes the client sent after the request.
	proxyCopy(readerConn{Conn: conn, r: rd}, peer)
}

func (s *HTTPServer) listen(network, addr string) (net.Listener, error) {
	if s.tlsRequired {
		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return nil, err
		}

		return tls.Listen(network, addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	}

	return net.Listen(network, addr)
}

// ListenAndServe is used to create a listener and serve on it
func (s *HTTPServer) ListenAndServe(network, addr string) error {
	server, err := s.listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen tcp failed: %w", err)
	}
	defer func(server net.Listener) {
		_ = server.Close()
	}(server)
	for {
		conn, err := server.Accept()
		if err != nil {
			return fmt.Errorf("accept request failed: %w", err)
		}
		go func(conn net.Conn) {
			s.serve(conn)
		}(conn)
	}
}
