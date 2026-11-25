package wireproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
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
