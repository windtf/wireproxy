package wireproxy

import (
	"bytes"
	"io"
	"net"
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
