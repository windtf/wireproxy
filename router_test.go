package wireproxy

import (
	"regexp"
	"testing"
)

func mustCompile(t *testing.T, patterns ...string) []*regexp.Regexp {
	t.Helper()
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("compile %q: %v", p, err)
		}
		out = append(out, re)
	}
	return out
}

func TestDomainRouterShouldTunnel(t *testing.T) {
	patterns := mustCompile(t, `^(.*\.)?example\.com$`, `^ipinfo\.io$`)

	cases := []struct {
		name string
		host string
		want bool
	}{
		{"exact match", "example.com", true},
		{"subdomain match", "www.example.com", true},
		{"deep subdomain match", "a.b.example.com", true},
		{"second pattern exact", "ipinfo.io", true},
		{"trailing dot stripped", "example.com.", true},
		{"uppercase normalised", "WWW.EXAMPLE.COM", true},
		{"no match", "other.net", false},
		{"partial no match (suffix guard)", "notexample.com", false},
		{"ip literal no match", "93.184.216.34", false},
	}

	router := NewDomainRouter(patterns, false)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := router.route(c.host); got != c.want {
				t.Fatalf("route(%q) = %v, want %v", c.host, got, c.want)
			}
		})
	}
}

func TestDomainRouterEmptyTunnelsEverything(t *testing.T) {
	router := NewDomainRouter(nil, false)
	for _, host := range []string{"anything.example", "1.2.3.4", ""} {
		if !router.route(host) {
			t.Fatalf("empty whitelist should tunnel %q", host)
		}
	}

	// A nil router must also default to tunnelling (legacy behaviour).
	var nilRouter *DomainRouter
	if !nilRouter.route("example.com") {
		t.Fatal("nil router should tunnel everything")
	}
}

func TestHostFromAddr(t *testing.T) {
	cases := map[string]string{
		"example.com:443": "example.com",
		"example.com":     "example.com",
		"1.2.3.4:80":      "1.2.3.4",
		"[::1]:443":       "::1",
	}
	for in, want := range cases {
		if got := hostFromAddr(in); got != want {
			t.Fatalf("hostFromAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRegexListMultiLine(t *testing.T) {
	// Multiple TunnelDomains lines each parse as one full regex; commas inside a
	// quantifier must survive (no comma-splitting).
	const config = `
[Socks5]
BindAddress = 127.0.0.1:25344
TunnelDomains = ^(.*\.)?example\.com$
TunnelDomains = ^cache[0-9]{2,4}\.cdn\.net$
LogDomains = true`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	section := iniData.Section("Socks5")

	spawner, err := parseSocks5Config(section)
	if err != nil {
		t.Fatal(err)
	}
	cfg := spawner.(*Socks5Config)

	if len(cfg.TunnelDomains) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(cfg.TunnelDomains))
	}
	if !cfg.LogDomains {
		t.Fatal("expected LogDomains=true")
	}

	router := NewDomainRouter(cfg.TunnelDomains, cfg.LogDomains)
	if !router.route("www.example.com") {
		t.Fatal("www.example.com should tunnel")
	}
	if !router.route("cache123.cdn.net") {
		t.Fatal("cache123.cdn.net should tunnel (quantifier with comma)")
	}
	if router.route("evil.net") {
		t.Fatal("evil.net should be direct")
	}
}

func TestParseRegexListInvalidRejected(t *testing.T) {
	const config = `
[http]
BindAddress = 127.0.0.1:25345
TunnelDomains = ^(unclosed`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	section := iniData.Section("http")

	if _, err := parseHTTPConfig(section); err == nil {
		t.Fatal("expected invalid regex to be rejected")
	}
}

func TestParseConfigDefaultsNoRouting(t *testing.T) {
	const config = `
[SNI]
BindAddress = 0.0.0.0:443`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	spawner, err := parseSNIConfig(iniData.Section("SNI"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := spawner.(*SNIConfig)
	if len(cfg.TunnelDomains) != 0 || cfg.LogDomains {
		t.Fatal("defaults should be empty TunnelDomains and LogDomains=false")
	}
}
