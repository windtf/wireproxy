package wireproxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testKeyA = "0000000000000000000000000000000000000000000000000000000000000001"
	testKeyB = "0000000000000000000000000000000000000000000000000000000000000002"
)

type fakeIpcDevice struct {
	get    string
	getErr error
	sets   []string
}

func (f *fakeIpcDevice) IpcGet() (string, error) { return f.get, f.getErr }

func (f *fakeIpcDevice) IpcSet(request string) error {
	f.sets = append(f.sets, request)
	return nil
}

func ipcPeer(key, endpoint string, handshake time.Time) string {
	var sec, nsec int64
	if !handshake.IsZero() {
		sec, nsec = handshake.Unix(), int64(handshake.Nanosecond())
	}
	return fmt.Sprintf("public_key=%s\nendpoint=%s\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\ntx_bytes=1\nrx_bytes=1\n",
		key, endpoint, sec, nsec)
}

func fixedResolver(addr string, err error, calls *int) func(string) (string, error) {
	return func(string) (string, error) {
		*calls++
		return addr, err
	}
}

func hostPeer(key string) PeerConfig {
	endpoint := "1.1.1.1:51820"
	return PeerConfig{PublicKey: key, Endpoint: &endpoint, EndpointRaw: "vpn.example.com:51820"}
}

func TestReresolveStaleHandshakeChangedIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: "private_key=aa\nlisten_port=0\n" +
		ipcPeer(testKeyA, "1.1.1.1:51820", now.Add(-10*time.Minute))}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("2.2.2.2:51820", nil, &calls), now)

	if calls != 1 {
		t.Fatalf("expected 1 resolve, got %d", calls)
	}
	want := "public_key=" + testKeyA + "\nupdate_only=true\nendpoint=2.2.2.2:51820\n"
	if len(dev.sets) != 1 || dev.sets[0] != want {
		t.Fatalf("unexpected IpcSet calls: %q", dev.sets)
	}
}

func TestReresolveNeverHandshaken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: ipcPeer(testKeyA, "1.1.1.1:51820", time.Time{})}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("2.2.2.2:51820", nil, &calls), now)

	if calls != 1 || len(dev.sets) != 1 {
		t.Fatalf("expected 1 resolve and 1 IpcSet, got %d and %d", calls, len(dev.sets))
	}
}

func TestReresolveFreshHandshakeDoesNotResolve(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: ipcPeer(testKeyA, "1.1.1.1:51820", now.Add(-30*time.Second))}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("2.2.2.2:51820", nil, &calls), now)

	if calls != 0 || len(dev.sets) != 0 {
		t.Fatalf("expected no resolve and no IpcSet, got %d and %d", calls, len(dev.sets))
	}
}

func TestReresolveUnchangedIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: ipcPeer(testKeyA, "1.1.1.1:51820", now.Add(-10*time.Minute))}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("1.1.1.1:51820", nil, &calls), now)

	if calls != 1 || len(dev.sets) != 0 {
		t.Fatalf("expected 1 resolve and no IpcSet, got %d and %d", calls, len(dev.sets))
	}
}

func TestReresolveErrorKeepsEndpoint(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: ipcPeer(testKeyA, "1.1.1.1:51820", now.Add(-10*time.Minute))}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("", errors.New("no such host"), &calls), now)

	if calls != 1 || len(dev.sets) != 0 {
		t.Fatalf("expected 1 resolve and no IpcSet, got %d and %d", calls, len(dev.sets))
	}
}

func TestReresolveIpcGetErrorDoesNothing(t *testing.T) {
	dev := &fakeIpcDevice{getErr: errors.New("boom")}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA)}, fixedResolver("2.2.2.2:51820", nil, &calls), time.Now())

	if calls != 0 || len(dev.sets) != 0 {
		t.Fatalf("expected no resolve and no IpcSet, got %d and %d", calls, len(dev.sets))
	}
}

func TestReresolveOnlyUpdatesStalePeer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dev := &fakeIpcDevice{get: ipcPeer(testKeyA, "1.1.1.1:51820", now.Add(-5*time.Second)) +
		ipcPeer(testKeyB, "[2001:db8::1]:51820", now.Add(-10*time.Minute))}
	calls := 0

	reresolveEndpoints(dev, []PeerConfig{hostPeer(testKeyA), hostPeer(testKeyB)}, fixedResolver("[2001:db8::2]:51820", nil, &calls), now)

	want := "public_key=" + testKeyB + "\nupdate_only=true\nendpoint=[2001:db8::2]:51820\n"
	if calls != 1 || len(dev.sets) != 1 || dev.sets[0] != want {
		t.Fatalf("unexpected result: %d resolves, IpcSet calls %q", calls, dev.sets)
	}
}

func TestReresolvablePeers(t *testing.T) {
	const config = `
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = 94.140.11.15:51820

[Peer]
PublicKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Endpoint = [::1]:51820

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
`
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	var peers []PeerConfig
	if err := ParsePeers(iniData, &peers); err != nil {
		t.Fatal(err)
	}
	if got := reresolvablePeers(peers); len(got) != 0 {
		t.Fatalf("expected no re-resolvable peers, got %d", len(got))
	}

	// localhost resolves without network access
	hostConfig := strings.Replace(config, "94.140.11.15", "LocalHost", 1)
	iniData, err = loadIniConfig(hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	peers = nil
	if err := ParsePeers(iniData, &peers); err != nil {
		t.Fatal(err)
	}
	got := reresolvablePeers(peers)
	if len(got) != 1 || got[0].EndpointRaw != "localhost:51820" {
		t.Fatalf("expected the hostname peer only, got %+v", got)
	}
}

func TestEndpointReresolveIntervalConfig(t *testing.T) {
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
		{"", 30, false},
		{"EndpointReresolveInterval = 10", 10, false},
		{"EndpointReresolveInterval = 0", 0, false},
		{"EndpointReresolveInterval = -1", 0, true},
		{"EndpointReresolveInterval = abc", 0, true},
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
		if err == nil && cfg.EndpointReresolveInterval != tt.want {
			t.Fatalf("%q: expected %d, got %d", tt.extra, tt.want, cfg.EndpointReresolveInterval)
		}
	}
}

func TestParsePeerStatusesHandshakeKeyOrder(t *testing.T) {
	ipc := "public_key=aa\nlast_handshake_time_nsec=5\nlast_handshake_time_sec=100\nendpoint=192.0.2.1:51820\n"
	status := parsePeerStatuses(ipc)["aa"]
	if status == nil {
		t.Fatal("peer aa not parsed")
	}
	if want := time.Unix(100, 5); !status.lastHandshake.Equal(want) {
		t.Fatalf("lastHandshake = %v, want %v", status.lastHandshake, want)
	}
}
