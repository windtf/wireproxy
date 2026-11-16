package wireproxy

import (
	"github.com/go-ini/ini"
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

func TestParseUDPServerTunnelConfig(t *testing.T) {
	const config = `
[UDPServerTunnel]
ListenPort = 19132
Target = 127.0.0.1:19132
InactivityTimeout = 30`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	spawner, err := parseUDPServerTunnelConfig(iniData.Section("UDPServerTunnel"))
	if err != nil {
		t.Fatal(err)
	}

	cfg, ok := spawner.(*UDPServerTunnelConfig)
	if !ok {
		t.Fatalf("unexpected spawner type %T", spawner)
	}
	if cfg.ListenPort != 19132 {
		t.Fatalf("ListenPort = %d, want 19132", cfg.ListenPort)
	}
	if cfg.Target != "127.0.0.1:19132" {
		t.Fatalf("Target = %q, want 127.0.0.1:19132", cfg.Target)
	}
	if cfg.InactivityTimeout != 30 {
		t.Fatalf("InactivityTimeout = %d, want 30", cfg.InactivityTimeout)
	}
}

func TestParseUDPServerTunnelRejectsInvalidConfig(t *testing.T) {
	cases := map[string]string{
		"missing listen port": `
[UDPServerTunnel]
Target = 127.0.0.1:19132`,
		"missing target": `
[UDPServerTunnel]
ListenPort = 19132`,
		"negative timeout": `
[UDPServerTunnel]
ListenPort = 19132
Target = 127.0.0.1:19132
InactivityTimeout = -1`,
	}

	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			iniData, err := loadIniConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseUDPServerTunnelConfig(iniData.Section("UDPServerTunnel")); err == nil {
				t.Fatal("expected invalid config to be rejected")
			}
		})
	}
}
