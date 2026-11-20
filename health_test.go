package wireproxy

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// base64 of the 32 bytes 00..00 01 and 00..00 02
	handshakeKeyA = "handshake:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	handshakeKeyB = "handshake:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="
	handshakeHexA = "0000000000000000000000000000000000000000000000000000000000000001"
	handshakeHexB = "0000000000000000000000000000000000000000000000000000000000000002"
)

func TestHandshakeRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	maxAge := 2 * time.Minute
	ipc := func(a, b int64) string {
		return fmt.Sprintf("private_key=aa\npublic_key=%s\nendpoint=192.0.2.1:51820\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=0\n"+
			"public_key=%s\nendpoint=192.0.2.2:51820\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=0\n", handshakeHexA, a, handshakeHexB, b)
	}

	tests := []struct {
		name      string
		ipc       string
		wantStale bool
		wantA     uint64
		wantB     uint64
	}{
		{"all fresh", ipc(now.Unix()-10, now.Unix()-100), false, uint64(now.Unix() - 10), uint64(now.Unix() - 100)},
		{"one stale", ipc(now.Unix()-10, now.Unix()-300), true, uint64(now.Unix() - 10), uint64(now.Unix() - 300)},
		{"one never", ipc(now.Unix()-10, 0), true, uint64(now.Unix() - 10), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, stale := handshakeRecords(tt.ipc, maxAge, now)
			if stale != tt.wantStale {
				t.Fatalf("stale = %v, want %v", stale, tt.wantStale)
			}
			if len(records) != 2 || records[handshakeKeyA] != tt.wantA || records[handshakeKeyB] != tt.wantB {
				t.Fatalf("unexpected records: %v", records)
			}
		})
	}

	if records, stale := handshakeRecords("private_key=aa\n", maxAge, now); stale || len(records) != 0 {
		t.Fatalf("no peers should not be stale, got %v %v", stale, records)
	}

	t.Run("peer without an endpoint is ignored", func(t *testing.T) {
		// B has no endpoint and never handshook; only A counts.
		noEndpoint := fmt.Sprintf("private_key=aa\npublic_key=%s\nendpoint=192.0.2.1:51820\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=0\n"+
			"public_key=%s\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n", handshakeHexA, now.Unix()-10, handshakeHexB)
		records, stale := handshakeRecords(noEndpoint, maxAge, now)
		if stale {
			t.Fatal("a peer without an endpoint must not make the check stale")
		}
		if len(records) != 1 || records[handshakeKeyA] != uint64(now.Unix()-10) {
			t.Fatalf("unexpected records: %v", records)
		}
	})
}

func newReadyzTun(t *testing.T, maxHandshakeAge int) VirtualTun {
	t.Helper()
	return newReadyzTunPeer(t, maxHandshakeAge, true)
}

func newReadyzTunPeer(t *testing.T, maxHandshakeAge int, withEndpoint bool) VirtualTun {
	t.Helper()
	tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)

	// The device is not brought up, so no handshake can ever happen.
	request := "private_key=" + handshakeHexB + "\npublic_key=" + handshakeHexA + "\n"
	if withEndpoint {
		request += "endpoint=192.0.2.1:51820\n"
	}
	request += "allowed_ip=0.0.0.0/0\n"
	if err := dev.IpcSet(request); err != nil {
		t.Fatal(err)
	}

	return VirtualTun{
		Dev:            dev,
		Conf:           &DeviceConfig{CheckAliveInterval: 5, MaxHandshakeAge: maxHandshakeAge},
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}
}

func TestReadyzMaxHandshakeAge(t *testing.T) {
	t.Run("unset keeps the existing behaviour", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newReadyzTun(t, 0).ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
	})

	t.Run("peer that never handshook is unavailable", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newReadyzTun(t, 120).ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
		if strings.TrimSpace(rec.Body.String()) != `{"`+handshakeKeyA+`":0}` {
			t.Fatalf("unexpected body %q", rec.Body.String())
		}
	})

	t.Run("peer without an endpoint is ignored", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newReadyzTunPeer(t, 120, false).ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
	})
}

// TestReadyzFreshHandshake brings up two wireguard devices over loopback and
// expects /readyz of the initiator to turn 200 once they have handshaked.
func TestReadyzFreshHandshake(t *testing.T) {
	keyHex := func(seed byte) (private, public string) {
		raw := make([]byte, 32)
		raw[1] = seed
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw), hex.EncodeToString(key.PublicKey().Bytes())
	}
	newDev := func() (*device.Device, *netstack.Net) {
		tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		t.Cleanup(dev.Close)
		return dev, tnet
	}

	privA, pubA := keyHex(1)
	privB, pubB := keyHex(2)

	devB, _ := newDev()
	if err := devB.IpcSet("private_key=" + privB + "\nlisten_port=0\npublic_key=" + pubA + "\nallowed_ip=0.0.0.0/0\n"); err != nil {
		t.Fatal(err)
	}
	if err := devB.Up(); err != nil {
		t.Fatal(err)
	}
	ipc, err := devB.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var portB string
	for _, line := range strings.Split(ipc, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			portB = v
		}
	}
	if _, err := strconv.Atoi(portB); err != nil {
		t.Fatalf("no listen_port in %q", ipc)
	}

	devA, _ := newDev()
	if err := devA.IpcSet("private_key=" + privA + "\nlisten_port=0\npublic_key=" + pubB +
		"\nendpoint=127.0.0.1:" + portB + "\npersistent_keepalive_interval=1\nallowed_ip=0.0.0.0/0\n"); err != nil {
		t.Fatal(err)
	}
	if err := devA.Up(); err != nil {
		t.Fatal(err)
	}

	tun := VirtualTun{
		Dev:            devA,
		Conf:           &DeviceConfig{CheckAliveInterval: 5, MaxHandshakeAge: 120},
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		tun.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code == http.StatusOK {
			var body map[string]uint64
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 1 {
				t.Fatalf("unexpected body %q", rec.Body.String())
			}
			for _, sec := range body {
				if sec == 0 {
					t.Fatalf("200 with an empty handshake time: %q", rec.Body.String())
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no fresh handshake within 10s, last got %d %q", rec.Code, rec.Body.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMaxHandshakeAgeConfig(t *testing.T) {
	const base = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
`
	tests := []struct {
		extra   string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"MaxHandshakeAge = 180", 180, false},
		{"MaxHandshakeAge = 0", 0, false},
		{"MaxHandshakeAge = -1", 0, true},
		{"MaxHandshakeAge = abc", 0, true},
	}
	for _, tt := range tests {
		var cfg DeviceConfig
		iniData, err := loadIniConfig(base + tt.extra)
		if err != nil {
			t.Fatal(err)
		}
		err = ParseInterface(iniData, &cfg)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%q: unexpected error state: %v", tt.extra, err)
		}
		if err == nil && cfg.MaxHandshakeAge != tt.want {
			t.Fatalf("%q: expected %d, got %d", tt.extra, tt.want, cfg.MaxHandshakeAge)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	serve := func(status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/readyz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"1.1.1.1":0}`))
		}))
	}
	addr := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

	ok := serve(http.StatusOK)
	defer ok.Close()
	if err := Healthcheck(addr(ok), time.Second); err != nil {
		t.Fatalf("expected healthy, got %v", err)
	}

	bad := serve(http.StatusServiceUnavailable)
	defer bad.Close()
	err := Healthcheck(addr(bad), time.Second)
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), `{"1.1.1.1":0}`) {
		t.Fatalf("expected a 503 error with the body, got %v", err)
	}

	closed := serve(http.StatusOK)
	closedAddr := addr(closed)
	closed.Close()
	if err := Healthcheck(closedAddr, time.Second); err == nil {
		t.Fatal("expected an error for an unreachable address")
	}
}
