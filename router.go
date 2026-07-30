package wireproxy

import (
	"log"
	"net"
	"regexp"
	"strings"
)

// DomainRouter decides whether a connection to a given host is routed through
// the WireGuard tunnel (host matches the whitelist) or dialed directly.
//
// An empty pattern list means "tunnel everything", preserving the legacy
// behaviour where every proxied connection goes through the tunnel.
type DomainRouter struct {
	patterns []*regexp.Regexp
	logNames bool
}

// NewDomainRouter builds a DomainRouter from compiled regex patterns. When
// logNames is true, every routing decision is logged so users can discover
// which domains their applications reach (and thus what to whitelist).
func NewDomainRouter(patterns []*regexp.Regexp, logNames bool) *DomainRouter {
	return &DomainRouter{patterns: patterns, logNames: logNames}
}

// shouldTunnel reports whether host should be routed through the tunnel.
func (r *DomainRouter) shouldTunnel(host string) bool {
	if r == nil || len(r.patterns) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range r.patterns {
		if p.MatchString(host) {
			return true
		}
	}
	return false
}

// route decides how to dial host and, when logging is enabled, records the
// decision. It returns true when the connection should use the tunnel.
func (r *DomainRouter) route(host string) bool {
	tunnel := r.shouldTunnel(host)
	if r != nil && r.logNames {
		dest := "DIRECT"
		if tunnel {
			dest = "TUNNEL"
		}
		log.Printf("route: %s -> %s\n", host, dest)
	}
	return tunnel
}

// hostFromAddr extracts the host portion from a "host:port" address, falling
// back to the whole string when there is no port.
func hostFromAddr(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
