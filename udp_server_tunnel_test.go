package wireproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startUDPEcho starts a loopback UDP echo server and returns its listener.
func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	return conn
}

func TestServeUDPServerTunnelForwards(t *testing.T) {
	target := startUDPEcho(t)

	// Stand in for the WireGuard-side packet listener.
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go serveUDPServerTunnel(listener, target.LocalAddr().(*net.UDPAddr), 0)

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()

	payloads := [][]byte{[]byte("hello"), []byte("second datagram")}
	for _, payload := range payloads {
		if _, err := peer.WriteToUDP(payload, listener.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}

		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64*1024)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("reading forwarded response: %v", err)
		}
		if got := string(buf[:n]); got != string(payload) {
			t.Fatalf("got %q, want %q", got, payload)
		}
	}
}

// TestServeUDPServerTunnelOverNetstack verifies that the relay works with a
// listener created on the WireGuard netstack, which is how SpawnRoutine binds
// the server side.
func TestServeUDPServerTunnelOverNetstack(t *testing.T) {
	target := startUDPEcho(t)

	deviceAddr := netip.MustParseAddr("10.99.0.2")
	_, tnet, err := netstack.CreateNetTUN([]netip.Addr{deviceAddr}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := tnet.ListenUDP(&net.UDPAddr{IP: net.IP(deviceAddr.AsSlice()), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go serveUDPServerTunnel(listener, target.LocalAddr().(*net.UDPAddr), 0)

	client, err := tnet.DialUDP(nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("netstack")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64*1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("reading netstack response: %v", err)
	}
	if got := string(buf[:n]); got != "netstack" {
		t.Fatalf("got %q, want %q", got, "netstack")
	}
}

func TestServeUDPServerTunnelReturnsWhenListenerCloses(t *testing.T) {
	target := startUDPEcho(t)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		serveUDPServerTunnel(listener, target.LocalAddr().(*net.UDPAddr), 0)
		close(done)
	}()

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveUDPServerTunnel did not return after listener close")
	}
}
