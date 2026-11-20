package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestDNSCache(ttl time.Duration) (*dnsCache, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	c := newDNSCache(ttl)
	c.now = clock.Now
	return c, clock
}

func TestDNSCacheHit(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	calls := 0
	fn := func(context.Context, string) ([]string, error) {
		calls++
		return []string{"1.2.3.4"}, nil
	}

	for _, name := range []string{"example.com", "EXAMPLE.com"} {
		addrs, err := c.lookup(context.Background(), name, fn)
		if err != nil || len(addrs) != 1 || addrs[0] != "1.2.3.4" {
			t.Fatalf("lookup(%q) = %v, %v", name, addrs, err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 lookup, got %d", calls)
	}
}

func TestDNSCacheReturnsCopy(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	fn := func(context.Context, string) ([]string, error) { return []string{"1.2.3.4"}, nil }

	first, _ := c.lookup(context.Background(), "example.com", fn)
	first[0] = "changed"
	second, _ := c.lookup(context.Background(), "example.com", fn)
	if second[0] != "1.2.3.4" {
		t.Fatalf("cached answer was modified by caller: %v", second)
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	c, clock := newTestDNSCache(time.Minute)
	calls := 0
	fn := func(context.Context, string) ([]string, error) {
		calls++
		return []string{fmt.Sprintf("10.0.0.%d", calls)}, nil
	}

	_, _ = c.lookup(context.Background(), "example.com", fn)
	clock.Advance(59 * time.Second)
	if _, _ = c.lookup(context.Background(), "example.com", fn); calls != 1 {
		t.Fatalf("expected cache hit before TTL, got %d lookups", calls)
	}
	clock.Advance(time.Second)
	addrs, _ := c.lookup(context.Background(), "example.com", fn)
	if calls != 2 || addrs[0] != "10.0.0.2" {
		t.Fatalf("expected a fresh lookup after TTL, got %d lookups, %v", calls, addrs)
	}
}

func TestDNSCacheDoesNotCacheErrorsOrEmpty(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	calls := 0
	lookupErr := errors.New("lookup failed")
	fn := func(context.Context, string) ([]string, error) {
		calls++
		switch calls {
		case 1:
			return nil, lookupErr
		case 2:
			return []string{}, nil
		}
		return []string{"1.2.3.4"}, nil
	}

	if _, err := c.lookup(context.Background(), "example.com", fn); !errors.Is(err, lookupErr) {
		t.Fatalf("expected lookup error, got %v", err)
	}
	if addrs, err := c.lookup(context.Background(), "example.com", fn); err != nil || len(addrs) != 0 {
		t.Fatalf("expected empty answer, got %v, %v", addrs, err)
	}
	if addrs, err := c.lookup(context.Background(), "example.com", fn); err != nil || len(addrs) != 1 {
		t.Fatalf("expected success, got %v, %v", addrs, err)
	}
	if _, _ = c.lookup(context.Background(), "example.com", fn); calls != 3 {
		t.Fatalf("expected 3 lookups (errors and empty answers not cached), got %d", calls)
	}
}

func TestDNSCacheDisabled(t *testing.T) {
	c := newDNSCache(0)
	if c != nil {
		t.Fatal("expected nil cache for zero TTL")
	}
	calls := 0
	fn := func(context.Context, string) ([]string, error) {
		calls++
		return []string{"1.2.3.4"}, nil
	}
	for i := 0; i < 3; i++ {
		if _, err := c.lookup(context.Background(), "example.com", fn); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("expected a lookup per call, got %d", calls)
	}
}

func TestDNSCacheBounded(t *testing.T) {
	c, clock := newTestDNSCache(time.Minute)
	fn := func(context.Context, string) ([]string, error) { return []string{"1.2.3.4"}, nil }

	for i := 0; i < dnsCacheMaxEntries+10; i++ {
		_, _ = c.lookup(context.Background(), fmt.Sprintf("host%d.example.com", i), fn)
	}
	if len(c.entries) != dnsCacheMaxEntries {
		t.Fatalf("expected %d entries while all are live, got %d", dnsCacheMaxEntries, len(c.entries))
	}

	clock.Advance(time.Minute)
	_, _ = c.lookup(context.Background(), "fresh.example.com", fn)
	if len(c.entries) != 1 {
		t.Fatalf("expected expired entries to be swept, got %d entries", len(c.entries))
	}
}

func TestDNSCacheConcurrent(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	var calls atomic.Int32
	fn := func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return []string{"1.2.3.4"}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				addrs, err := c.lookup(context.Background(), fmt.Sprintf("host%d.example.com", j%5), fn)
				if err != nil || len(addrs) != 1 {
					t.Errorf("lookup = %v, %v", addrs, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if n := calls.Load(); n < 5 {
		t.Fatalf("expected at least one lookup per name, got %d", n)
	}
}

func TestVirtualTunCopiesShareCache(t *testing.T) {
	vt := VirtualTun{cache: newDNSCache(time.Minute)}
	copyVT := vt
	if vt.cache != copyVT.cache {
		t.Fatal("expected copies of VirtualTun to share one cache")
	}
}
