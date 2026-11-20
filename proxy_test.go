package wireproxy

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client.(*net.TCPConn), server
}

func TestProxyCopyHalfClose(t *testing.T) {
	client, proxyA := tcpPair(t)
	proxyB, origin := tcpPair(t)

	done := make(chan struct{})
	go func() {
		proxyCopy(proxyA, proxyB)
		close(done)
	}()

	// The origin only answers after it has seen the end of the request.
	go func() {
		req, _ := io.ReadAll(origin)
		_, _ = origin.Write(append([]byte("reply to "), req...))
		_ = origin.Close()
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply to request" {
		t.Fatalf("got %q after half-close", got)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyCopy did not return after both directions finished")
	}
}

func TestProxyCopyLargeBidirectional(t *testing.T) {
	client, proxyA := tcpPair(t)
	proxyB, origin := tcpPair(t)

	go proxyCopy(proxyA, proxyB)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = origin.SetDeadline(time.Now().Add(10 * time.Second))

	send := func(c *net.TCPConn) {
		_, _ = c.Write(payload)
		_ = c.CloseWrite()
	}
	go send(client)
	go send(origin)

	for name, c := range map[string]*net.TCPConn{"client": client, "origin": origin} {
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s received %d bytes, want %d", name, len(got), len(payload))
		}
	}
}

// A connection without CloseWrite cannot signal EOF, so both sides are closed.
func TestProxyCopyClosesBothWithoutCloseWrite(t *testing.T) {
	pipeClient, pipeProxy := net.Pipe()
	proxyB, origin := tcpPair(t)

	done := make(chan struct{})
	go func() {
		proxyCopy(pipeProxy, proxyB)
		close(done)
	}()

	_ = origin.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyCopy did not return")
	}
	_ = pipeClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := pipeClient.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF on the other side, got %v", err)
	}
}

type failingWriterTo struct{ io.Reader }

func (failingWriterTo) WriteTo(io.Writer) (int64, error) { panic("WriteTo used") }

type failingReaderFrom struct{ bytes.Buffer }

func (*failingReaderFrom) ReadFrom(io.Reader) (int64, error) { panic("ReadFrom used") }

func TestCopyPooledUsesBuffer(t *testing.T) {
	var dst failingReaderFrom
	n, err := copyPooled(&dst, failingWriterTo{bytes.NewReader([]byte("data"))})
	if err != nil || n != 4 || dst.String() != "data" {
		t.Fatalf("copyPooled = %d, %v, %q", n, err, dst.String())
	}
}

func setProxyIdleTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := proxyIdleTimeout
	proxyIdleTimeout = d
	t.Cleanup(func() { proxyIdleTimeout = old })
}

// After one side half-closes, a silent other side must not linger forever.
func TestProxyCopyIdleAfterHalfClose(t *testing.T) {
	setProxyIdleTimeout(t, 100*time.Millisecond)
	client, proxyA := tcpPair(t)
	proxyB, origin := tcpPair(t)

	done := make(chan struct{})
	go func() {
		proxyCopy(proxyA, proxyB)
		close(done)
	}()

	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The origin sees EOF but never replies or closes.
	_ = origin.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := origin.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("origin read: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyCopy did not give up on the idle half-closed connection")
	}
}

// The idle timeout is not an absolute deadline: it restarts on every read.
func TestProxyCopyIdleTimeoutResetsOnActivity(t *testing.T) {
	setProxyIdleTimeout(t, 200*time.Millisecond)
	client, proxyA := tcpPair(t)
	proxyB, origin := tcpPair(t)

	go proxyCopy(proxyA, proxyB)

	go func() {
		for i := 0; i < 6; i++ {
			time.Sleep(80 * time.Millisecond)
			_, _ = origin.Write([]byte("x"))
		}
		_ = origin.Close()
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "xxxxxx" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// opaqueErrConn blocks in Read until it is closed, then fails with an error
// that is not net.ErrClosed (like gonet after a local Close).
type opaqueErrConn struct {
	closed chan struct{}
	err    error
}

func (c *opaqueErrConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, c.err
}
func (c *opaqueErrConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *opaqueErrConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func captureErrorLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := errorLogger
	errorLogger = log.New(&buf, "", 0)
	t.Cleanup(func() { errorLogger = old })
	return &buf
}

func TestProxyCopyDoesNotLogOwnClose(t *testing.T) {
	buf := captureErrorLog(t)
	client, proxyA := tcpPair(t)
	fake := &opaqueErrConn{closed: make(chan struct{}), err: errors.New("endpoint is closed for receive")}

	done := make(chan struct{})
	go func() {
		proxyCopy(proxyA, fake)
		close(done)
	}()

	// EOF from the client: fake has no CloseWrite, so both sides get closed,
	// which makes fake's Read fail with an opaque error.
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyCopy did not return")
	}
	if buf.Len() != 0 {
		t.Fatalf("logged an error caused by our own close: %q", buf.String())
	}
}

func TestProxyCopyLogsRealError(t *testing.T) {
	buf := captureErrorLog(t)
	_, proxyA := tcpPair(t)
	fake := &failingReadConn{err: errors.New("boom")}

	proxyCopy(proxyA, fake)
	if !strings.Contains(buf.String(), "boom") {
		t.Fatalf("real error not logged: %q", buf.String())
	}
}

type failingReadConn struct{ err error }

func (c *failingReadConn) Read([]byte) (int, error)    { return 0, c.err }
func (c *failingReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *failingReadConn) Close() error                { return nil }
