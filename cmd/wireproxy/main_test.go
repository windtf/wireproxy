package main

import (
	"fmt"
	"net"
	"regexp"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/windtf/wireproxy"
)

func ruleStrings(rules []landlock.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[fmt.Sprint(r)] = true
	}
	return out
}

func TestNetworkRules(t *testing.T) {
	domains := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	info := "127.0.0.1:9000"

	tests := []struct {
		name            string
		sections        []wireproxy.RoutineSpawner
		systemDNS       bool
		restrictConnect bool
		want            []string
		notWant         []string
	}{
		{
			name: "tunnel only with DNS restricts connect",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080"},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
				&wireproxy.TCPClientTunnelConfig{BindAddress: &net.TCPAddr{Port: 2222}},
			},
			restrictConnect: true,
			want: []string{
				"ALLOW {bind_tcp} on TCP port 9000",
				"ALLOW {bind_tcp} on TCP port 8080",
				"ALLOW {bind_tcp} on TCP port 2222",
				"ALLOW {connect_tcp} on TCP port 5432",
				"ALLOW {connect_tcp} on TCP port 53",
			},
		},
		{
			name: "split routing HTTP restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080", TunnelDomains: domains},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 8080", "ALLOW {bind_tcp} on TCP port 9000"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 5432", "ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "split routing SOCKS5 restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.Socks5Config{BindAddress: "127.0.0.1:1080", TunnelDomains: domains},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 1080"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "split routing SNI restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.SNIConfig{BindAddress: "127.0.0.1:8443", TunnelDomains: domains},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 8443"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "system DNS restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.Socks5Config{BindAddress: "127.0.0.1:1080"},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
			},
			systemDNS: true,
			want:      []string{"ALLOW {bind_tcp} on TCP port 1080"},
			notWant:   []string{"ALLOW {connect_tcp} on TCP port 5432", "ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "logging without domains still tunnels everything",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080", LogDomains: true},
			},
			restrictConnect: true,
			want:            []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, restrictConnect := networkRules(tt.sections, &info, tt.systemDNS)
			if restrictConnect != tt.restrictConnect {
				t.Fatalf("restrictConnect = %v, want %v", restrictConnect, tt.restrictConnect)
			}
			got := ruleStrings(rules)
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("missing rule %q in %v", w, got)
				}
			}
			for _, w := range tt.notWant {
				if got[w] {
					t.Errorf("unexpected rule %q", w)
				}
			}
		})
	}
}

func TestResolverFiles(t *testing.T) {
	have := map[string]bool{}
	for _, f := range resolverFiles {
		have[f] = true
	}
	for _, f := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"} {
		if !have[f] {
			t.Errorf("%s is not readable after lockdown", f)
		}
	}
}
