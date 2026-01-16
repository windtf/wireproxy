package wireproxy

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v2"
)

// NATInfo holds the discovered NAT mapping information
type NATInfo struct {
	PublicIP   netip.Addr
	PublicPort uint16
	LocalPort  uint16
}

// DefaultSTUNServers is the list of STUN servers to try
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.stunprotocol.org:3478",
}

// DiscoverNAT performs STUN discovery to find our public IP and port
func DiscoverNAT(localPort uint16, stunServers []string) (*NATInfo, error) {
	if len(stunServers) == 0 {
		stunServers = DefaultSTUNServers
	}

	// Bind to the specified local port
	localAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(localPort),
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to port %d: %w", localPort, err)
	}
	defer conn.Close()

	// Get the actual bound port (in case localPort was 0)
	boundAddr := conn.LocalAddr().(*net.UDPAddr)
	actualLocalPort := uint16(boundAddr.Port)

	var lastErr error
	for _, server := range stunServers {
		info, err := querySTUNServer(conn, server, actualLocalPort)
		if err != nil {
			lastErr = err
			continue
		}
		return info, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no STUN servers configured")
}

func querySTUNServer(conn *net.UDPConn, server string, localPort uint16) (*NATInfo, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server %s: %w", server, err)
	}

	// Build STUN Binding Request
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send request
	_, err = conn.WriteToUDP(message.Raw, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// Parse response
	response := new(stun.Message)
	response.Raw = buf[:n]
	if err := response.Decode(); err != nil {
		return nil, fmt.Errorf("failed to decode STUN response: %w", err)
	}

	// Extract XOR-MAPPED-ADDRESS
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(response); err != nil {
		// Try regular MAPPED-ADDRESS as fallback
		var mappedAddr stun.MappedAddress
		if err := mappedAddr.GetFrom(response); err != nil {
			return nil, fmt.Errorf("failed to get mapped address from STUN response: %w", err)
		}
		addr, ok := netip.AddrFromSlice(mappedAddr.IP)
		if !ok {
			return nil, fmt.Errorf("invalid IP address in STUN response")
		}
		return &NATInfo{
			PublicIP:   addr,
			PublicPort: uint16(mappedAddr.Port),
			LocalPort:  localPort,
		}, nil
	}

	addr, ok := netip.AddrFromSlice(xorAddr.IP)
	if !ok {
		return nil, fmt.Errorf("invalid IP address in STUN response")
	}

	return &NATInfo{
		PublicIP:   addr,
		PublicPort: uint16(xorAddr.Port),
		LocalPort:  localPort,
	}, nil
}

// MaintainNATMapping sends periodic STUN requests to keep the NAT mapping alive
// Returns a stop function to cancel the maintenance goroutine
func MaintainNATMapping(localPort uint16, interval time.Duration) (stop func()) {
	if interval == 0 {
		interval = 20 * time.Second
	}

	stopCh := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Use first server for keepalive
				_, _ = DiscoverNAT(localPort, DefaultSTUNServers[:1])
			case <-stopCh:
				return
			}
		}
	}()

	return func() {
		close(stopCh)
	}
}

// String returns a human-readable representation of NATInfo
func (n *NATInfo) String() string {
	return fmt.Sprintf("%s:%d", n.PublicIP, n.PublicPort)
}
