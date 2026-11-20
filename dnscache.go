package wireproxy

import (
	"context"
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
