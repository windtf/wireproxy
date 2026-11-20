package wireproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

// A client that connects and closes without sending anything (a port probe or
// load balancer health check) is not an error, but a truncated request is.
func TestHTTPServerReadRequestLogging(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// serveAfter has a client write write (if not empty) and close, then
	// returns what serve logged for that connection.
	serveAfter := func(write string) string {
		logs.Reset()
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if write != "" {
			if _, err := client.Write([]byte(write)); err != nil {
				t.Fatal(err)
			}
		}
		_ = client.Close()
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		(&HTTPServer{}).serve(server)
		return logs.String()
	}

	if got := serveAfter(""); got != "" {
		t.Errorf("empty connection logged %q, want nothing", got)
	}
	if got := serveAfter("GET http://example.test/ HT"); !strings.Contains(got, "read request failed") {
		t.Errorf("truncated request logged %q, want a read request failure", got)
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

// startRawOrigin accepts connections and hands each to handle.
func startRawOrigin(t *testing.T, handle func(conn net.Conn)) *HTTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	return &HTTPServer{
		dial: func(network, address string) (net.Conn, error) {
			return net.Dial(network, ln.Addr().String())
		},
	}
}

func TestHTTPServerPlainRequestChunkedBody(t *testing.T) {
	type seen struct {
		body string
		te   []string
	}
	got := make(chan seen, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{string(body), r.TransferEncoding}
		_, _ = w.Write([]byte("ok"))
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

	raw := "POST http://a.test/upload HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	if _, err := clientConn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response: %v, %v", resp, err)
	}

	select {
	case s := <-got:
		if s.body != "hello world" || len(s.te) != 1 || s.te[0] != "chunked" {
			t.Fatalf("origin saw %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive the request")
	}
}

func TestHTTPServerExpectContinue(t *testing.T) {
	// net/http answers "100 Continue" when the handler reads the body.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("got " + string(body)))
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

	headers := "POST http://a.test/ HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
	if _, err := clientConn.Write([]byte(headers)); err != nil {
		t.Fatal(err)
	}

	// Like curl, send the body only after the 100 Continue.
	rd := bufio.NewReader(clientConn)
	interim, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatalf("no interim response before the body was sent: %v", err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("interim status %d", interim.StatusCode)
	}
	if _, err := clientConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "got hello" {
		t.Fatalf("final response %d %q", resp.StatusCode, body)
	}
}

func TestHTTPServerUpgrade(t *testing.T) {
	server := startRawOrigin(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Header.Get("Upgrade") != "websocket" || !strings.EqualFold(req.Header.Get("Connection"), "Upgrade") ||
			req.Header.Get("Proxy-Authorization") != "" {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		// "frame" is sent in the same write as the 101.
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nframe"))
		_, _ = io.Copy(conn, br)
	})
	server.auth = CredentialValidator{"u", "p"}
	server.authRequired = true
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	raw := "GET http://a.test/ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Proxy-Authorization: Basic dTpw\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := clientConn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}

	rd := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("response %d %v", resp.StatusCode, resp.Header)
	}

	buf := make([]byte, len("frame"))
	if _, err := io.ReadFull(rd, buf); err != nil || string(buf) != "frame" {
		t.Fatalf("bytes after the 101 were lost: %q, %v", buf, err)
	}
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 4)
	if _, err := io.ReadFull(rd, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel did not echo: %q, %v", buf, err)
	}
}

// An origin that ignores "Connection: close" and keeps the connection open
// must not keep the client waiting after a complete response.
func TestHTTPServerPlainResponseEndsAtFraming(t *testing.T) {
	server := startRawOrigin(t, func(conn net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		_, _ = io.Copy(io.Discard, conn) // never closes by itself
	})
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := clientConn.Write([]byte("GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client connection was not closed after the response: %v", err)
	}
	if !strings.HasSuffix(string(all), "\r\n\r\nok") {
		t.Fatalf("unexpected response %q", all)
	}
}

// An origin that stalls mid-response is cut off after the idle timeout.
func TestHTTPServerPlainResponseIdleTimeout(t *testing.T) {
	setProxyIdleTimeout(t, 100*time.Millisecond)
	server := startRawOrigin(t, func(conn net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npart"))
		_, _ = io.Copy(io.Discard, conn)
	})
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := clientConn.Write([]byte("GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// The truncated response ends in an error or EOF, not a deadline timeout.
	_, err = io.ReadAll(clientConn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("proxy did not cut off the stalled origin: %v", err)
	}
}

func TestHTTPServerPlainResponseHeadersAndTrailers(t *testing.T) {
	server := startRawOrigin(t, func(conn net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Trailer: X-Sum\r\n" +
			"Connection: keep-alive, X-Custom-Hop\r\n" +
			"Keep-Alive: timeout=5\r\n" +
			"Proxy-Authenticate: Basic\r\n" +
			"X-Custom-Hop: 1\r\n" +
			"X-Keep-Me: yes\r\n\r\n" +
			"5\r\nhello\r\n0\r\nX-Sum: abc\r\n\r\n"))
		_, _ = io.Copy(io.Discard, conn)
	})
	addr := startTestProxy(t, server)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := clientConn.Write([]byte("GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "hello" {
		t.Fatalf("body %q, %v", body, err)
	}

	for _, name := range []string{"Keep-Alive", "Proxy-Authenticate", "X-Custom-Hop"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("client saw %s=%q", name, v)
		}
	}
	if resp.Header.Get("X-Keep-Me") != "yes" {
		t.Errorf("end-to-end header dropped: %v", resp.Header)
	}
	if !resp.Close {
		t.Errorf("expected Connection: close, headers %v", resp.Header)
	}
	if got := resp.Trailer.Get("X-Sum"); got != "abc" {
		t.Errorf("trailer X-Sum = %q, want abc (trailer %v)", got, resp.Trailer)
	}
}
