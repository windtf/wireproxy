package wireproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// dnsCacheMaxEntries bounds the number of cached names. Expired entries are
// swept when an insert would reach it; if every entry is still live the new
// answer is simply not cached.
const dnsCacheMaxEntries = 1024

type dnsCacheEntry struct {
	addrs   []string
	expires time.Time
}

// dnsCache caches successful hostname lookups for a fixed TTL.
// A nil *dnsCache is valid and never caches.
type dnsCache struct {
	ttl time.Duration
	// now is the clock, replaceable in tests
	now func() time.Time

	mu      sync.Mutex
	entries map[string]dnsCacheEntry
}

// newDNSCache returns a cache holding answers for ttl, or nil (no caching) if ttl is not positive.
func newDNSCache(ttl time.Duration) *dnsCache {
	if ttl <= 0 {
		return nil
	}
	return &dnsCache{ttl: ttl, now: time.Now, entries: make(map[string]dnsCacheEntry)}
}

// lookup returns the cached answer for name, or calls fn and caches its result.
// Errors and empty answers are not cached. Concurrent misses for the same name
// each call fn; the last answer stored wins.
func (c *dnsCache) lookup(ctx context.Context, name string, fn func(context.Context, string) ([]string, error)) ([]string, error) {
	if c == nil {
		return fn(ctx, name)
	}

	key := strings.ToLower(name)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && !c.now().Before(entry.expires) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	if ok {
		return slices.Clone(entry.addrs), nil
	}

	addrs, err := fn(ctx, name)
	if err != nil || len(addrs) == 0 {
		return addrs, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.entries) >= dnsCacheMaxEntries {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	if _, exists := c.entries[key]; exists || len(c.entries) < dnsCacheMaxEntries {
		c.entries[key] = dnsCacheEntry{addrs: slices.Clone(addrs), expires: now.Add(c.ttl)}
	}
	return addrs, nil
}

// dialCached dials address, resolving a hostname through cache and trying each
// returned address in order. It mirrors the loop in netstack's DialContext, which
// would otherwise do its own uncached lookup: the context is checked before each
// attempt, a deadline is shared out across the remaining addresses, and the first
// dial error is returned if none succeeds. Cancellation and timeouts are reported
// as a *net.OpError, as netstack does. IP literals, a nil cache and
// unparsable addresses are passed to dial unchanged.
func dialCached(
	ctx context.Context,
	cache *dnsCache,
	lookup func(context.Context, string) ([]string, error),
	dial func(ctx context.Context, network, address string) (net.Conn, error),
	network, address string,
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if cache == nil || err != nil {
		return dial(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return dial(ctx, network, address)
	}

	addrs, err := cache.lookup(ctx, host, lookup)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var suitable []string
	for _, saddr := range addrs {
		ip, err := netip.ParseAddr(saddr)
		if err != nil {
			continue
		}
		if (ip.Is4() && strings.HasSuffix(network, "6")) || (ip.Is6() && strings.HasSuffix(network, "4")) {
			continue
		}
		suitable = append(suitable, saddr)
	}
	if len(suitable) == 0 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("no suitable address found for: " + host)}
	}

	var firstErr error
	for i, saddr := range suitable {
		select {
		case <-ctx.Done():
			return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
		default:
		}

		dialCtx := ctx
		if deadline, ok := ctx.Deadline(); ok {
			attempt, err := attemptDeadline(time.Now(), deadline, len(suitable)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Net: network, Err: err}
				}
				break
			}
			if attempt.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, attempt)
				defer cancel()
			}
		}

		conn, err := dial(dialCtx, network, net.JoinHostPort(saddr, port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// attemptDeadline splits the time left until deadline evenly across the addresses
// still to try, with a floor of 2s (or whatever remains, if less), like netstack
// and net.Dialer do.
func attemptDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return time.Time{}, context.DeadlineExceeded
	}
	const floor = 2 * time.Second
	timeout := remaining / time.Duration(addrsRemaining)
	if timeout < floor {
		timeout = min(floor, remaining)
	}
	return now.Add(timeout), nil
}
