package wireproxy

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// reresolveHandshakeAge is how old the last handshake of a peer has to be
// before its endpoint is resolved again: REKEY_AFTER_TIME (120s) plus a
// margin, the same threshold as wireguard-tools' contrib/reresolve-dns.
const reresolveHandshakeAge = 135 * time.Second

// ipcDevice is the part of *device.Device used to update peer endpoints.
type ipcDevice interface {
	IpcGet() (string, error)
	IpcSet(string) error
}

// peerStatus is what IpcGet reports about a peer that is needed to decide
// whether its endpoint should be resolved again.
type peerStatus struct {
	endpoint      string
	lastHandshake time.Time // zero if there has never been a handshake
	handshakeSec  int64
	handshakeNsec int64
}

// parsePeerStatuses extracts the endpoint and last handshake time of every
// peer in an IpcGet response, keyed by hex public key.
func parsePeerStatuses(ipc string) map[string]*peerStatus {
	statuses := make(map[string]*peerStatus)
	var current *peerStatus
	for _, line := range strings.Split(ipc, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			current = &peerStatus{}
			statuses[value] = current
		case "endpoint":
			if current != nil {
				current.endpoint = value
			}
		case "last_handshake_time_sec":
			if current != nil {
				current.handshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if current != nil {
				current.handshakeNsec, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	// The seconds and nanoseconds keys may arrive in either order, so the
	// handshake time is assembled once the whole response has been read.
	for _, status := range statuses {
		if status.handshakeSec != 0 {
			status.lastHandshake = time.Unix(status.handshakeSec, status.handshakeNsec)
		}
	}
	return statuses
}

// reresolvablePeers returns the peers whose endpoint is a hostname, which can
// change over time. Peers without an endpoint or with an IP literal are skipped.
func reresolvablePeers(peers []PeerConfig) []PeerConfig {
	var result []PeerConfig
	for _, peer := range peers {
		if peer.Endpoint == nil || peer.EndpointRaw == "" {
			continue
		}
		host, _, err := net.SplitHostPort(peer.EndpointRaw)
		if err != nil {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		result = append(result, peer)
	}
	return result
}

// reresolveEndpoints resolves the endpoint of every given peer again if its
// last handshake is older than reresolveHandshakeAge (or never happened), and
// updates the peer if the resolved address differs from the current one.
// Failures keep the current endpoint.
func reresolveEndpoints(dev ipcDevice, peers []PeerConfig, resolve func(string) (string, error), now time.Time) {
	get, err := dev.IpcGet()
	if err != nil {
		errorLogger.Printf("Failed to get device state to re-resolve endpoints: %s\n", err.Error())
		return
	}
	statuses := parsePeerStatuses(get)

	for _, peer := range peers {
		status, ok := statuses[peer.PublicKey]
		if !ok {
			continue
		}
		if !status.lastHandshake.IsZero() && now.Sub(status.lastHandshake) <= reresolveHandshakeAge {
			continue
		}

		endpoint, err := resolve(peer.EndpointRaw)
		if err != nil {
			errorLogger.Printf("Failed to resolve endpoint %s: %s\n", peer.EndpointRaw, err.Error())
			continue
		}
		if endpoint == status.endpoint {
			continue
		}

		request := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", peer.PublicKey, endpoint)
		if err := dev.IpcSet(request); err != nil {
			errorLogger.Printf("Failed to update endpoint of %s: %s\n", peer.EndpointRaw, err.Error())
			continue
		}
		log.Printf("Endpoint %s changed from %s to %s\n", peer.EndpointRaw, status.endpoint, endpoint)
	}
}

// StartEndpointReresolve periodically resolves hostname endpoints again, so
// that a peer behind a dynamic DNS name is found after its IP address changes.
// It does nothing if disabled or if no peer has a hostname endpoint.
func (d VirtualTun) StartEndpointReresolve() {
	peers := reresolvablePeers(d.Conf.Peers)
	if d.Conf.EndpointReresolveInterval <= 0 || len(peers) == 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(d.Conf.EndpointReresolveInterval) * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			reresolveEndpoints(d.Dev, peers, resolveIPPAndPort, now)
		}
	}()
}
