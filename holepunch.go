package wireproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultRendezvousServer is the public rendezvous server for connection exchange
const DefaultRendezvousServer = "http://localhost:8080"

// HolePunchConfig holds the configuration for hole punching mode
type HolePunchConfig struct {
	// Mode: "host" exposes a service, "join" connects to one
	Mode string

	// LocalPort for WireGuard to bind to (0 = random)
	LocalPort uint16

	// ExposePort: port to expose to peer (host mode)
	ExposePort int

	// BindPort: local port to bind for accessing remote service (join mode)
	BindPort int

	// Code: wormhole code for joining (join mode)
	Code string

	// RendezvousServer: URL of rendezvous server
	RendezvousServer string

	// STUNServers: list of STUN servers to use
	STUNServers []string
}

// ConnectionInfo represents the info exchanged between peers
type ConnectionInfo struct {
	PublicKey string `json:"pubkey"`
	Endpoint  string `json:"endpoint"`
	TunnelIP  string `json:"tunnel_ip"`
}

// HolePunchSession manages an active hole punch session
type HolePunchSession struct {
	Config     *HolePunchConfig
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key
	NATInfo    *NATInfo
	PeerInfo   *ConnectionInfo
	Code       string
}

// wordList for generating human-readable codes
var wordList = []string{
	"apple", "banana", "cherry", "dragon", "eagle", "falcon", "grape", "honey",
	"island", "jungle", "kiwi", "lemon", "mango", "nectar", "orange", "peach",
	"quince", "raven", "sunset", "tiger", "umbrella", "violet", "walrus", "xenon",
	"yellow", "zebra", "anchor", "breeze", "castle", "dolphin", "ember", "forest",
}

// GenerateCode creates a human-readable wormhole code
func GenerateCode() string {
	var b [3]byte
	rand.Read(b[:])

	num := int(b[0]) % 100
	word1 := wordList[int(b[1])%len(wordList)]
	word2 := wordList[int(b[2])%len(wordList)]

	return fmt.Sprintf("%d-%s-%s", num, word1, word2)
}

// NewHolePunchSession creates a new hole punch session
func NewHolePunchSession(config *HolePunchConfig) (*HolePunchSession, error) {
	// Generate WireGuard keypair
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	session := &HolePunchSession{
		Config:     config,
		PrivateKey: privateKey,
		PublicKey:  privateKey.PublicKey(),
	}

	// Discover NAT
	session.NATInfo, err = DiscoverNAT(config.LocalPort, config.STUNServers)
	if err != nil {
		return nil, fmt.Errorf("NAT discovery failed: %w", err)
	}

	// Generate or use provided code
	if config.Mode == "host" {
		session.Code = GenerateCode()
	} else {
		session.Code = config.Code
	}

	return session, nil
}

// GetConnectionString returns the connection string to share with peer
func (s *HolePunchSession) GetConnectionString() string {
	pubKeyB64 := base64.StdEncoding.EncodeToString(s.PublicKey[:])
	return fmt.Sprintf("hp://%s@%s", pubKeyB64, s.NATInfo.String())
}

// ParseConnectionString parses a connection string into ConnectionInfo
func ParseConnectionString(connStr string) (*ConnectionInfo, error) {
	// Format: hp://BASE64_PUBKEY@IP:PORT
	if !strings.HasPrefix(connStr, "hp://") {
		return nil, fmt.Errorf("invalid connection string format")
	}

	connStr = strings.TrimPrefix(connStr, "hp://")
	parts := strings.Split(connStr, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid connection string format")
	}

	return &ConnectionInfo{
		PublicKey: parts[0],
		Endpoint:  parts[1],
	}, nil
}

// rendezvousPayload is the JSON payload for rendezvous API
type rendezvousPayload struct {
	Code     string `json:"code"`
	PubKey   string `json:"pubkey"`
	Endpoint string `json:"endpoint"`
	TunnelIP string `json:"tunnel_ip"`
}

// ExchangeViaRendezvous exchanges connection info with peer via rendezvous server
func (s *HolePunchSession) ExchangeViaRendezvous() error {
	server := s.Config.RendezvousServer
	if server == "" {
		server = DefaultRendezvousServer
	}

	// Determine tunnel IP based on mode
	tunnelIP := "10.0.0.1"
	if s.Config.Mode == "join" {
		tunnelIP = "10.0.0.2"
	}

	// Prepare our info
	payload := rendezvousPayload{
		Code:     s.Code,
		PubKey:   base64.StdEncoding.EncodeToString(s.PublicKey[:]),
		Endpoint: s.NATInfo.String(),
		TunnelIP: tunnelIP,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// POST to rendezvous server
	client := &http.Client{Timeout: 60 * time.Second}

	for attempt := 0; attempt < 60; attempt++ {
		resp, err := client.Post(server+"/session", "application/json", bytes.NewReader(body))
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		if resp.StatusCode == http.StatusAccepted {
			// Peer hasn't connected yet, wait and retry
			resp.Body.Close()
			time.Sleep(time.Second)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			// Peer info received
			var peerPayload rendezvousPayload
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err := json.Unmarshal(respBody, &peerPayload); err != nil {
				return fmt.Errorf("failed to parse peer info: %w", err)
			}

			s.PeerInfo = &ConnectionInfo{
				PublicKey: peerPayload.PubKey,
				Endpoint:  peerPayload.Endpoint,
				TunnelIP:  peerPayload.TunnelIP,
			}
			return nil
		}

		resp.Body.Close()
		return fmt.Errorf("rendezvous server returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("timeout waiting for peer")
}

// BuildWireGuardConfig generates a WireGuard configuration for the session
func (s *HolePunchSession) BuildWireGuardConfig() (*DeviceConfig, error) {
	if s.PeerInfo == nil {
		return nil, fmt.Errorf("peer info not available, call ExchangeViaRendezvous first")
	}

	// Decode peer's public key
	peerPubKeyBytes, err := base64.StdEncoding.DecodeString(s.PeerInfo.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	// Determine our tunnel IP
	tunnelIP := "10.0.0.1"
	peerTunnelIP := "10.0.0.2"
	if s.Config.Mode == "join" {
		tunnelIP = "10.0.0.2"
		peerTunnelIP = "10.0.0.1"
	}

	tunnelAddr, _ := netip.ParseAddr(tunnelIP)
	peerPrefix, _ := netip.ParsePrefix(peerTunnelIP + "/32")

	listenPort := int(s.NATInfo.LocalPort)

	return &DeviceConfig{
		SecretKey:  fmt.Sprintf("%x", s.PrivateKey[:]),
		Endpoint:   []netip.Addr{tunnelAddr},
		ListenPort: &listenPort,
		MTU:        1420,
		Peers: []PeerConfig{
			{
				PublicKey:    fmt.Sprintf("%x", peerPubKeyBytes),
				Endpoint:     &s.PeerInfo.Endpoint,
				AllowedIPs:   []netip.Prefix{peerPrefix},
				KeepAlive:    10,
				PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}, nil
}
