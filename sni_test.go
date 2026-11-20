package wireproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// captureConn records what a TLS client writes and then fails the handshake.
type captureConn struct {
	net.Conn
	written []byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *captureConn) Read([]byte) (int, error) { return 0, errors.New("capture only") }

func clientHelloFor(t *testing.T, serverName string) []byte {
	t.Helper()
	cc := &captureConn{}
	_ = tls.Client(cc, &tls.Config{ServerName: serverName}).Handshake()
	if len(cc.written) == 0 {
		t.Fatal("no ClientHello captured")
	}
	return cc.written
}

func TestSNIProxyHalfClose(t *testing.T) {
	hello := clientHelloFor(t, "example.test")

	client, proxyConn := tcpPair(t)
	proxyBackend, backend := tcpPair(t)

	var dialed string
	dial := func(network, address string) (net.Conn, error) {
		dialed = address
		return proxyBackend, nil
	}

	done := make(chan error, 1)
	go func() { done <- sniProxyForward(dial, proxyConn) }()

	// The backend answers only once the client has finished sending.
	go func() {
		req, _ := io.ReadAll(backend)
		_, _ = backend.Write([]byte("got "))
		_, _ = backend.Write([]byte{byte(len(req) % 256)})
		_ = backend.Close()
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("got "), byte(len(hello)%256)); string(reply) != string(want) {
		t.Fatalf("reply %q, want %q", reply, want)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sniProxyForward did not return")
	}
	if dialed != "example.test:443" {
		t.Fatalf("dialed %q", dialed)
	}
}
