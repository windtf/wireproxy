package wireproxy

// TLS SNI extraction approach based on Andrew Ayer's sniproxy:
// https://www.agwa.name/blog/post/writing_an_sni_proxy_in_go/media/sniproxy.go

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func peekClientHello(conn net.Conn) (string, io.ReadWriteCloser, error) {
	peekedBytes := new(bytes.Buffer)
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: io.TeeReader(conn, peekedBytes)}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	wrappedConn := struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		Reader: io.MultiReader(peekedBytes, conn),
		Writer: conn,
		Closer: conn,
	}

	var serverName string
	if hello != nil {
		serverName = hello.ServerName
		err = nil
	}

	return serverName, wrappedConn, err
}

// Get SNI hostname, dial out through tunnel, then proxy data
func sniProxyForward(dial func(string, string) (net.Conn, error), conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline failed: %w", err)
	}

	hostname, clientConn, err := peekClientHello(conn)
	if err != nil {
		return fmt.Errorf("peek client hello failed: %w", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear read deadline failed: %w", err)
	}

	if hostname == "" {
		return fmt.Errorf("no SNI hostname in ClientHello")
	}

	target := net.JoinHostPort(hostname, "443")
	backendConn, err := dial("tcp", target)
	if err != nil {
		return fmt.Errorf("tun tcp dial failed: %w", err)
	}

	go connForward(clientConn, backendConn)
	go connForward(backendConn, clientConn)

	return nil
}

func sniServe(dial func(string, string) (net.Conn, error), conn net.Conn) {
	if err := sniProxyForward(dial, conn); err != nil {
		log.Printf("SNI proxy: %s\n", err)
		_ = conn.Close()
	}
}
