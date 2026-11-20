package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handshakeRecords reports the last handshake time of every peer found in an
// IpcGet response as unix seconds (0 if there has never been one), keyed by
// "handshake:<base64 public key>". stale is true if any checked peer has no
// handshake or one older than maxAge.
//
// Peers with no Endpoint in the configuration only answer handshakes and have
// never connected out, so none can be expected of them: they are left out of the
// verdict and flagged in records with a "handshake_skipped:<base64 public key>"
// entry of 1. The configuration is consulted rather than the IPC "endpoint" line,
// which wireguard also reports for endpoints learned from incoming packets.
func handshakeRecords(ipc string, peers []PeerConfig, maxAge time.Duration, now time.Time) (records map[string]uint64, stale bool) {
	configured := make(map[string]bool)
	for _, peer := range peers {
		if peer.Endpoint != nil {
			configured[base64Key(peer.PublicKey)] = true
		}
	}

	records = make(map[string]uint64)
	skipped := make(map[string]bool)
	var key64 string
	for _, line := range strings.Split(ipc, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			key64 = base64Key(value)
			records["handshake:"+key64] = 0
			if !configured[key64] {
				skipped[key64] = true
			}
		case "last_handshake_time_sec":
			if sec, err := strconv.ParseUint(value, 10, 63); err == nil && key64 != "" {
				records["handshake:"+key64] = sec
			}
		}
	}

	for peer, record := range records {
		if skipped[strings.TrimPrefix(peer, "handshake:")] {
			continue
		}
		if record == 0 || now.Sub(time.Unix(int64(record), 0)) > maxAge {
			stale = true
		}
	}
	for peer := range skipped {
		records["handshake_skipped:"+peer] = 1
	}
	return records, stale
}

// base64Key converts a wireguard key given as hex (as in IpcGet and the parsed
// configuration) to base64; a key that is not hex is returned unchanged.
func base64Key(key string) string {
	if raw, err := hex.DecodeString(key); err == nil {
		return base64.StdEncoding.EncodeToString(raw)
	}
	return key
}

// Healthcheck requests /readyz from the health endpoint listening on addr
// (the value of --info) and returns an error unless it responds with 200.
func Healthcheck(addr string, timeout time.Duration) error {
	client := http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + addr + "/readyz")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unhealthy: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
