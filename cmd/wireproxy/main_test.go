package main

import (
	"testing"

	"github.com/windtf/wireproxy"
	"golang.zx2c4.com/wireguard/device"
)

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level      string
		silent     bool
		wantApp    wireproxy.LogLevel
		wantDevice int
	}{
		{"error", false, wireproxy.LogError, device.LogLevelError},
		{"info", false, wireproxy.LogInfo, device.LogLevelError},
		{"debug", false, wireproxy.LogDebug, device.LogLevelVerbose},
		{"info", true, wireproxy.LogError, device.LogLevelError},
		{"debug", true, wireproxy.LogError, device.LogLevelError},
	}

	for _, tt := range tests {
		app, dev := logLevels(tt.level, tt.silent)
		if app != tt.wantApp || dev != tt.wantDevice {
			t.Errorf("logLevels(%q, %v) = %d, %d; want %d, %d", tt.level, tt.silent, app, dev, tt.wantApp, tt.wantDevice)
		}
	}
}
