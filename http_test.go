package wireproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
