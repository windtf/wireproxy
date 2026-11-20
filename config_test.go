package wireproxy

import (
	"github.com/go-ini/ini"
	"strings"
	"testing"
)

func loadIniConfig(config string) (*ini.File, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	return ini.LoadSources(iniOpt, []byte(config))
}

func TestWireguardConfWithoutSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/23
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithManyAddress(t *testing.T) {
	const config = `
[Interface]
PrivateKey = mBsVDahr1XIu9PPd17UmsDdB6E53nvmS47NbNqQCiFM=
Address = 100.96.0.190,2606:B300:FFFF:fe8a:2ac6:c7e8:b021:6f5f/128
DNS = 198.18.0.1,198.18.0.2

[Peer]
PublicKey = SHnh4C2aDXhp1gjIqceGhJrhOLSeNYcqWLKcYnzj00U=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 192.200.144.22:51820`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckAliveIntervalMustBePositive(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
CheckAlive = 1.1.1.1
CheckAliveInterval = 0

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	var cfg DeviceConfig
	if err := ParseInterface(iniData, &cfg); err == nil {
		t.Fatal("expected non-positive CheckAliveInterval to be rejected")
	}
}

func TestResolveCacheTTL(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    int
		wantErr bool
	}{
		{"unset", "[Resolve]\nResolveStrategy = ipv4", 0, false},
		{"positive", "[Resolve]\nCacheTTL = 60", 60, false},
		{"zero", "[Resolve]\nCacheTTL = 0", 0, false},
		{"negative", "[Resolve]\nCacheTTL = -1", 0, true},
		{"not a number", "[Resolve]\nCacheTTL = soon", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iniData, err := loadIniConfig(tt.config)
			if err != nil {
				t.Fatal(err)
			}

			cfg, err := parseResolveConfig(iniData.Section("Resolve"))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CacheTTL != tt.want {
				t.Fatalf("CacheTTL = %d, want %d", cfg.CacheTTL, tt.want)
			}
		})
	}
}

func TestResolveStrategy(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    string
		wantErr bool
	}{
		{"section without the key defaults to auto", "[Resolve]\nCacheTTL = 60", "auto", false},
		{"auto", "[Resolve]\nResolveStrategy = auto", "auto", false},
		{"ipv4", "[Resolve]\nResolveStrategy = ipv4", "ipv4", false},
		{"ipv6", "[Resolve]\nResolveStrategy = ipv6", "ipv6", false},
		{"case-insensitive value is normalised", "[Resolve]\nResolveStrategy = IPv4", "ipv4", false},
		{"key name is case-insensitive", "[Resolve]\nresolvestrategy = ipv6", "ipv6", false},
		{"invalid value", "[Resolve]\nResolveStrategy = ipv5", "", true},
		{"empty value", "[Resolve]\nResolveStrategy =", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iniData, err := loadIniConfig(tt.config)
			if err != nil {
				t.Fatal(err)
			}

			cfg, err := parseResolveConfig(iniData.Section("Resolve"))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), "ResolveStrategy") {
					t.Fatalf("error does not name the key: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ResolveStrategy != tt.want {
				t.Fatalf("ResolveStrategy = %q, want %q", cfg.ResolveStrategy, tt.want)
			}
		})
	}
}

func TestInactivityTimeoutCannotBeNegative(t *testing.T) {
	const config = `
[UDPProxyTunnel]
BindAddress = 127.0.0.1:25346
Target = 1.1.1.1:53
InactivityTimeout = -1`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parseUDPProxyTunnelConfig(iniData.Section("UDPProxyTunnel")); err == nil {
		t.Fatal("expected negative InactivityTimeout to be rejected")
	}
}
