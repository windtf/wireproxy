package wireproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPServerServeGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok from upstream"))
	}))
	defer ts.Close()

	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, ts.Listener.Addr().String())
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server.serve(conn)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	req, err := http.NewRequest(http.MethodGet, "http://"+ts.Listener.Addr().String()+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := req.Write(clientConn); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != "ok from upstream" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestHTTPServerServeFailureClosesConn(t *testing.T) {
	server := &HTTPServer{}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server.serve(conn)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	// Send invalid HTTP request
	if _, err := clientConn.Write([]byte("INVALID\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1)
	_, err = clientConn.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF when server closes connection, got %v", err)
	}
}

// startTestProxy serves server on a loopback listener and returns its address.
func startTestProxy(t *testing.T, server *HTTPServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	return listener.Addr().String()
}

func TestHTTPServerStripsHopByHopHeaders(t *testing.T) {
	got := make(chan http.Header, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, ts.Listener.Addr().String())
		},
		auth:         CredentialValidator{"u", "p"},
		authRequired: true,
	}
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	raw := "GET http://" + ts.Listener.Addr().String() + "/ HTTP/1.1\r\n" +
		"Host: " + ts.Listener.Addr().String() + "\r\n" +
		"Proxy-Authorization: Basic dTpw\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Connection: keep-alive, X-Secret-Hop\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"X-Secret-Hop: 1\r\n" +
		"X-Keep-Me: yes\r\n\r\n"
	if _, err := clientConn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}

	select {
	case h := <-got:
		for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "X-Secret-Hop"} {
			if v := h.Get(name); v != "" {
				t.Errorf("origin saw %s=%q", name, v)
			}
		}
		if h.Get("X-Keep-Me") != "yes" {
			t.Errorf("end-to-end header dropped: %v", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive the request")
	}
}

// startEchoServer accepts connections and echoes everything back.
func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestHTTPServerConnectForwardsEarlyBytes(t *testing.T) {
	echo := startEchoServer(t)
	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, echo)
		},
	}
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	// The payload arrives in the same segment as the CONNECT request, so it
	// sits in the proxy's bufio.Reader.
	if _, err := clientConn.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nEARLY")); err != nil {
		t.Fatal(err)
	}

	rd := bufio.NewReader(clientConn)
	status, err := rd.ReadString('\n')
	if err != nil || status != "HTTP/1.1 200 Connection established\r\n" {
		t.Fatalf("unexpected status %q (err %v)", status, err)
	}
	if line, err := rd.ReadString('\n'); err != nil || line != "\r\n" {
		t.Fatalf("unexpected header terminator %q (err %v)", line, err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len("EARLY"))
	if _, err := io.ReadFull(rd, buf); err != nil {
		t.Fatalf("early bytes were not forwarded: %v", err)
	}
	if string(buf) != "EARLY" {
		t.Fatalf("unexpected echo %q", buf)
	}
}

func TestHTTPServerConnectHalfClose(t *testing.T) {
	// The origin replies only after the client has half-closed.
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = originLn.Close() }()
	go func() {
		conn, err := originLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("reply to "), req...))
	}()

	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, originLn.Addr().String())
		},
	}
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := clientConn.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(clientConn)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := clientConn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply to request" {
		t.Fatalf("got %q after half-close", got)
	}
}

func setReadRequestTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := httpReadRequestTimeout
	httpReadRequestTimeout = d
	t.Cleanup(func() { httpReadRequestTimeout = old })
}

func TestHTTPServerReadRequestTimeout(t *testing.T) {
	setReadRequestTimeout(t, 100*time.Millisecond)
	addr := startTestProxy(t, &HTTPServer{})

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	// An incomplete request line, then silence.
	if _, err := clientConn.Write([]byte("GET http://example.test/ HT")); err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected the proxy to close the idle connection, got %v", err)
	}
}

func TestHTTPServerReadDeadlineClearedForTunnel(t *testing.T) {
	setReadRequestTimeout(t, 100*time.Millisecond)
	echo := startEchoServer(t)
	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, echo)
		},
	}
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := clientConn.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(clientConn)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Stay idle for longer than the request timeout, then use the tunnel.
	time.Sleep(300 * time.Millisecond)
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(rd, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel closed by the request read deadline: %q, %v", buf, err)
	}
}

func TestHTTPServerForwardsNonGetMethods(t *testing.T) {
	type seen struct {
		method, body string
		close        bool
	}
	got := make(chan seen, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, string(body), r.Close}
		_, _ = w.Write([]byte("done"))
	}))
	defer ts.Close()

	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, ts.Listener.Addr().String())
		},
	}
	addr := startTestProxy(t, server)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		clientConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

		req, err := http.NewRequest(method, "http://"+ts.Listener.Addr().String()+"/x", strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if err := req.Write(clientConn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", method, resp.StatusCode)
		}
		_ = resp.Body.Close()
		_ = clientConn.Close()

		select {
		case s := <-got:
			if s.method != method || s.body != "payload" || !s.close {
				t.Fatalf("%s: origin saw %+v", method, s)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: origin did not receive the request", method)
		}
	}
}

// A keep-alive follow-up for another host must not be piped to the first origin.
func TestHTTPServerPlainRequestUsesOneOriginConnection(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("first"))
	}))
	defer ts.Close()

	server := &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, ts.Listener.Addr().String())
		},
	}
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	two := "GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n" +
		"GET http://b.test/ HTTP/1.1\r\nHost: b.test\r\n\r\n"
	if _, err := clientConn.Write([]byte(two)); err != nil {
		t.Fatal(err)
	}

	all, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("expected the proxy to close the client connection after the response: %v", err)
	}
	if n := strings.Count(string(all), "HTTP/1.1 200"); n != 1 {
		t.Fatalf("got %d responses, want 1: %q", n, all)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("origin saw %d requests, want 1", n)
	}
}
