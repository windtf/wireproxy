package wireproxy

import (
	"net"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// socks5UDPRoundTrip performs a SOCKS5 UDP ASSOCIATE handshake, sends one
// datagram to destination, and verifies that the echoed payload comes back
// through the relay.
func socks5UDPRoundTrip(t *testing.T, config *Socks5Config, vt *VirtualTun, destination string) {
	t.Helper()

	server := config.newServer(vt)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		_ = server.Serve(listener)
	}()

	control, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = control.Close() }()

	if _, err := control.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{statute.MethodNoAuth}).Bytes()); err != nil {
		t.Fatal(err)
	}
	methodReply, err := statute.ParseMethodReply(control)
	if err != nil {
		t.Fatal(err)
	}
	if methodReply.Method != statute.MethodNoAuth {
		t.Fatalf("negotiated method = %d, want no-auth", methodReply.Method)
	}

	associate := statute.Request{
		Version: statute.VersionSocks5,
		Command: statute.CommandAssociate,
		DstAddr: statute.AddrSpec{
			AddrType: statute.ATYPIPv4,
			IP:       net.IPv4zero,
			Port:     0,
		},
	}
	if _, err := control.Write(associate.Bytes()); err != nil {
		t.Fatal(err)
	}
	reply, err := statute.ParseReply(control)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Response != statute.RepSuccess {
		t.Fatalf("UDP ASSOCIATE reply = %d, want success", reply.Response)
	}

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	relay, err := net.ResolveUDPAddr("udp", reply.BndAddr.String())
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello over socks5 udp")
	datagram, err := statute.NewDatagram(destination, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(datagram.Bytes(), relay); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64*1024)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("reading UDP ASSOCIATE response: %v", err)
	}

	response, err := statute.ParseDatagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Data) != string(payload) {
		t.Fatalf("response payload = %q, want %q", response.Data, payload)
	}
}

// TestSocks5UDPAssociateForwards exercises the split-routing path with a
// destination that does not match TunnelDomains, so it is dialed directly.
func TestSocks5UDPAssociateForwards(t *testing.T) {
	echo := startUDPEcho(t)

	config := &Socks5Config{
		TunnelDomains: []*regexp.Regexp{regexp.MustCompile(`^tunnel\.invalid$`)},
	}
	socks5UDPRoundTrip(t, config, &VirtualTun{}, echo.LocalAddr().String())
}

// TestSocks5UDPAssociateTunnelsDatagram exercises the split-routing path with a
// destination that matches TunnelDomains, so the datagram is dialed through
// netstack just as it would be through WireGuard.
func TestSocks5UDPAssociateTunnelsDatagram(t *testing.T) {
	deviceAddr := netip.MustParseAddr("10.99.0.2")
	_, tnet, err := netstack.CreateNetTUN([]netip.Addr{deviceAddr}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}

	echo, err := tnet.ListenUDP(&net.UDPAddr{IP: net.IP(deviceAddr.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	config := &Socks5Config{
		TunnelDomains: []*regexp.Regexp{regexp.MustCompile(`^10\.99\.0\.2$`)},
	}
	vt := &VirtualTun{
		Tnet: tnet,
		Conf: &DeviceConfig{Endpoint: []netip.Addr{deviceAddr}},
	}

	socks5UDPRoundTrip(t, config, vt, echo.LocalAddr().String())
}
