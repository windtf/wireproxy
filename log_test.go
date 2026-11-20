package wireproxy

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// captureLog redirects the standard logger and restores it, together with the
// log level, when the test ends.
func captureLog(t *testing.T, level LogLevel) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	SetLogLevel(level)
	t.Cleanup(func() {
		log.SetOutput(orig)
		SetLogLevel(LogInfo)
	})
	return &buf
}

func TestLogLevelGating(t *testing.T) {
	tests := []struct {
		level     LogLevel
		wantInfo  bool
		wantDebug bool
	}{
		{LogError, false, false},
		{LogInfo, true, false},
		{LogDebug, true, true},
	}

	for _, tt := range tests {
		buf := captureLog(t, tt.level)
		infof("info line")
		debugf("debug line")
		out := buf.String()
		if got := strings.Contains(out, "info line"); got != tt.wantInfo {
			t.Errorf("level %d: info printed = %v, want %v", tt.level, got, tt.wantInfo)
		}
		if got := strings.Contains(out, "debug line"); got != tt.wantDebug {
			t.Errorf("level %d: debug printed = %v, want %v", tt.level, got, tt.wantDebug)
		}
	}
}

func TestHealthRequestLoggedOnlyAtDebug(t *testing.T) {
	vt := VirtualTun{
		PingRecord:     map[string]uint64{},
		PingRecordLock: new(sync.Mutex),
		Conf:           &DeviceConfig{},
	}

	for _, tt := range []struct {
		level LogLevel
		want  bool
	}{{LogError, false}, {LogInfo, false}, {LogDebug, true}} {
		buf := captureLog(t, tt.level)
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		vt.ServeHTTP(httptest.NewRecorder(), req)
		if got := strings.Contains(buf.String(), "Health metric request"); got != tt.want {
			t.Errorf("level %d: health request logged = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestResolveLoggedOnlyAtDebug(t *testing.T) {
	vt := VirtualTun{
		SystemDNS:     true,
		ResolveConfig: &ResolveConfig{ResolveStrategy: "ipv4"},
	}

	for _, tt := range []struct {
		level LogLevel
		want  bool
	}{{LogError, false}, {LogInfo, false}, {LogDebug, true}} {
		buf := captureLog(t, tt.level)
		// An IP literal resolves without touching the network.
		if _, _, err := vt.Resolve(context.Background(), "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "Resolving address for"); got != tt.want {
			t.Errorf("level %d: resolve logged = %v, want %v", tt.level, got, tt.want)
		}
	}
}
