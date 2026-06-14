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
	"sync"
	"time"
)

// Read only connection to extract ClientHello
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

// Get ClientHelloInfo from crypto/tls
func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

// Get SNI hostname, dial out through tunnel, then proxy data
func sniProxyForward(dial func(string, string) (net.Conn, error), clientConn net.Conn) error {
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline failed: %w", err)
	}

	clientHello, clientReader, err := peekClientHello(clientConn)
	if err != nil {
		return fmt.Errorf("peek client hello failed: %w", err)
	}

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear read deadline failed: %w", err)
	}

	hostname := clientHello.ServerName
	if hostname == "" {
		return fmt.Errorf("no SNI hostname in ClientHello")
	}

	target := net.JoinHostPort(hostname, "443")
	backendConn, err := dial("tcp", target)
	if err != nil {
		return fmt.Errorf("tun tcp dial failed: %w", err)
	}
	defer func() { _ = backendConn.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		_, _ = io.Copy(clientConn, backendConn)
		if tcpConn, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = tcpConn.CloseWrite()
		}
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(backendConn, clientReader)
		if tcpConn, ok := backendConn.(interface{ CloseWrite() error }); ok {
			_ = tcpConn.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()
	return nil
}

func sniServe(dial func(string, string) (net.Conn, error), conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := sniProxyForward(dial, conn); err != nil {
		log.Printf("SNI proxy: %s\n", err)
	}
}
