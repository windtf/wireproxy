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
// "handshake:<base64 public key>". stale is true if any peer has no handshake
// or one older than maxAge.
func handshakeRecords(ipc string, maxAge time.Duration, now time.Time) (records map[string]uint64, stale bool) {
	records = make(map[string]uint64)
	var name string
	for _, line := range strings.Split(ipc, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			name = value
			if raw, err := hex.DecodeString(value); err == nil {
				name = base64.StdEncoding.EncodeToString(raw)
			}
			name = "handshake:" + name
			records[name] = 0
		case "last_handshake_time_sec":
			if sec, err := strconv.ParseUint(value, 10, 63); err == nil && name != "" {
				records[name] = sec
			}
		}
	}

	for _, record := range records {
		if record == 0 || now.Sub(time.Unix(int64(record), 0)) > maxAge {
			stale = true
		}
	}
	return records, stale
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
