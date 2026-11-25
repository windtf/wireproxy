package wireproxy

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// runAssociateExchange feeds a scripted UDP ASSOCIATE reply to
// upstreamUDPAssociate and returns its result.
func runAssociateExchange(t *testing.T, reply []byte, config *UpstreamSocksConfig) (string, int, error) {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	go func() {
		defer func() { _ = server.Close() }()
		req := make([]byte, 10)
		if _, err := io.ReadFull(server, req); err != nil {
			t.Errorf("failed to read associate request: %v", err)
			return
		}
		want := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if !bytes.Equal(req, want) {
			t.Errorf("unexpected associate request: %v", req)
			return
		}
		_, _ = server.Write(reply)
	}()

	return upstreamUDPAssociate(client, config)
}

func TestUpstreamUDPAssociateIPv4(t *testing.T) {
	config := &UpstreamSocksConfig{Host: "upstream.example", Port: "1080"}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 192, 0, 2, 10, 0x10, 0xE1}
	host, port, err := runAssociateExchange(t, reply, config)
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.0.2.10" || port != 4321 {
		t.Fatalf("got %s:%d, want 192.0.2.10:4321", host, port)
	}
}

func TestUpstreamUDPAssociateWildcardUsesUpstreamHost(t *testing.T) {
	config := &UpstreamSocksConfig{Host: "upstream.example", Port: "1080"}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0xE1}
	host, port, err := runAssociateExchange(t, reply, config)
	if err != nil {
		t.Fatal(err)
	}
	if host != "upstream.example" || port != 4321 {
		t.Fatalf("got %s:%d, want upstream.example:4321", host, port)
	}
}

func TestUpstreamUDPAssociateIPv6LoopbackUsesUpstreamHost(t *testing.T) {
	config := &UpstreamSocksConfig{Host: "upstream.example", Port: "1080"}
	reply := append([]byte{0x05, 0x00, 0x00, 0x04}, net.IPv6loopback...)
	reply = append(reply, 0x10, 0xE1)
	host, port, err := runAssociateExchange(t, reply, config)
	if err != nil {
		t.Fatal(err)
	}
	if host != "upstream.example" || port != 4321 {
		t.Fatalf("got %s:%d, want upstream.example:4321", host, port)
	}
}

func TestUpstreamUDPAssociateDomain(t *testing.T) {
	config := &UpstreamSocksConfig{Host: "upstream.example", Port: "1080"}
	domain := "relay.example"
	reply := append([]byte{0x05, 0x00, 0x00, 0x03, byte(len(domain))}, []byte(domain)...)
	reply = append(reply, 0x10, 0xE1)
	host, port, err := runAssociateExchange(t, reply, config)
	if err != nil {
		t.Fatal(err)
	}
	if host != domain || port != 4321 {
		t.Fatalf("got %s:%d, want %s:4321", host, port, domain)
	}
}

func TestUpstreamUDPAssociateRejected(t *testing.T) {
	config := &UpstreamSocksConfig{Host: "upstream.example", Port: "1080"}
	reply := []byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, _, err := runAssociateExchange(t, reply, config); err == nil {
		t.Fatal("expected error for rejected associate")
	}
}
