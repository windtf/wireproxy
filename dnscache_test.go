package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
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
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				addrs, err := c.lookup(context.Background(), fmt.Sprintf("host%d.example.com", j%5), fn)
				if err != nil || len(addrs) != 1 {
					t.Errorf("lookup = %v, %v", addrs, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if n := calls.Load(); n < 5 {
		t.Fatalf("expected at least one lookup per name, got %d", n)
	}
}

type fakeDialer struct {
	mu        sync.Mutex
	calls     []string
	deadlines []time.Time // per call; zero if the context had none
	fail      map[string]bool
}

func (f *fakeDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+" "+address)
	deadline, _ := ctx.Deadline()
	f.deadlines = append(f.deadlines, deadline)
	if f.fail[address] {
		return nil, errors.New("dial failed: " + address)
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func countingLookup(calls *int, addrs ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		*calls++
		return addrs, nil
	}
}

func TestDialCachedUsesCache(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	lookups := 0
	d := &fakeDialer{}

	for i := 0; i < 2; i++ {
		conn, err := dialCached(context.Background(), c, countingLookup(&lookups, "1.2.3.4"), d.dial, "tcp", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if lookups != 1 {
		t.Fatalf("expected 1 lookup, got %d", lookups)
	}
	if want := []string{"tcp 1.2.3.4:443", "tcp 1.2.3.4:443"}; !slices.Equal(d.calls, want) {
		t.Fatalf("dials = %v, want %v", d.calls, want)
	}
}

func TestDialCachedFamilyFilter(t *testing.T) {
	tests := []struct {
		network string
		want    []string
	}{
		{"tcp", []string{"tcp 1.2.3.4:80"}},
		{"tcp4", []string{"tcp4 1.2.3.4:80"}},
		{"tcp6", []string{"tcp6 [2001:db8::1]:80"}},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			c, _ := newTestDNSCache(time.Minute)
			lookups := 0
			d := &fakeDialer{}
			addrs := []string{"1.2.3.4", "2001:db8::1"}
			conn, err := dialCached(context.Background(), c, countingLookup(&lookups, addrs...), d.dial, tt.network, "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if !slices.Equal(d.calls, tt.want) {
				t.Fatalf("dials = %v, want %v", d.calls, tt.want)
			}
		})
	}
}

func TestDialCachedNoSuitableAddress(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	lookups := 0
	d := &fakeDialer{}
	if _, err := dialCached(context.Background(), c, countingLookup(&lookups, "1.2.3.4"), d.dial, "tcp6", "example.com:80"); err == nil {
		t.Fatal("expected an error when no address matches the network")
	}
	if len(d.calls) != 0 {
		t.Fatalf("expected no dials, got %v", d.calls)
	}
}

func TestDialCachedFallsBackToNextAddress(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	lookups := 0
	d := &fakeDialer{fail: map[string]bool{"1.2.3.4:443": true}}

	conn, err := dialCached(context.Background(), c, countingLookup(&lookups, "1.2.3.4", "5.6.7.8"), d.dial, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if want := []string{"tcp 1.2.3.4:443", "tcp 5.6.7.8:443"}; !slices.Equal(d.calls, want) {
		t.Fatalf("dials = %v, want %v", d.calls, want)
	}

	d = &fakeDialer{fail: map[string]bool{"1.2.3.4:443": true, "5.6.7.8:443": true}}
	_, err = dialCached(context.Background(), c, countingLookup(&lookups, "1.2.3.4", "5.6.7.8"), d.dial, "tcp", "example.com:443")
	if err == nil || err.Error() != "dial failed: 1.2.3.4:443" {
		t.Fatalf("expected the first dial error, got %v", err)
	}
}

func TestDialCachedCancelledContext(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	lookups := 0
	d := &fakeDialer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := dialCached(ctx, c, countingLookup(&lookups, "1.2.3.4", "5.6.7.8"), d.dial, "tcp", "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(d.calls) != 0 {
		t.Fatalf("expected no dials, got %v", d.calls)
	}
}

func TestDialCachedContextErrorsAreOpErrors(t *testing.T) {
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"cancelled", cancelled, context.Canceled},
		{"deadline exceeded", expired, context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestDNSCache(time.Minute)
			lookups := 0
			d := &fakeDialer{}
			_, err := dialCached(tt.ctx, c, countingLookup(&lookups, "1.2.3.4"), d.dial, "tcp", "example.com:443")
			var opErr *net.OpError
			if !errors.As(err, &opErr) || opErr.Op != "dial" || opErr.Net != "tcp" {
				t.Fatalf("expected a dial *net.OpError for tcp, got %#v", err)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestDialCachedSharesDeadlineAcrossAddresses(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	lookups := 0
	d := &fakeDialer{fail: map[string]bool{"1.2.3.4:443": true}}
	overall := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), overall)
	defer cancel()

	conn, err := dialCached(ctx, c, countingLookup(&lookups, "1.2.3.4", "5.6.7.8"), d.dial, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if len(d.deadlines) != 2 {
		t.Fatalf("expected 2 dials, got %v", d.calls)
	}
	// first attempt gets about half the time left; the last gets all of it
	if !d.deadlines[0].Before(overall) || d.deadlines[0].Before(time.Now().Add(20*time.Second)) {
		t.Fatalf("first attempt deadline %v should be about half of the overall %v", d.deadlines[0], overall)
	}
	if !d.deadlines[1].Equal(overall) {
		t.Fatalf("last attempt deadline %v should be the overall %v", d.deadlines[1], overall)
	}
}

func TestAttemptDeadline(t *testing.T) {
	now := time.Unix(1000, 0)
	tests := []struct {
		name      string
		remaining time.Duration
		addrs     int
		want      time.Duration
		wantErr   bool
	}{
		{"single address", 10 * time.Second, 1, 10 * time.Second, false},
		{"split evenly", 10 * time.Second, 2, 5 * time.Second, false},
		{"floor", 10 * time.Second, 10, 2 * time.Second, false},
		{"floor capped at remaining", time.Second, 4, time.Second, false},
		{"expired", 0, 2, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := attemptDeadline(now, now.Add(tt.remaining), tt.addrs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != now.Add(tt.want) {
				t.Fatalf("deadline = %v, want %v", got.Sub(now), tt.want)
			}
		})
	}
}

func TestDialCachedLookupError(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	d := &fakeDialer{}
	lookup := func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	if _, err := dialCached(context.Background(), c, lookup, d.dial, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected the lookup error")
	}
	if len(d.calls) != 0 {
		t.Fatalf("expected no dials, got %v", d.calls)
	}
}

func TestDialCachedNilCacheLooksUpEveryTime(t *testing.T) {
	lookups := 0
	d := &fakeDialer{}
	for i := 0; i < 2; i++ {
		conn, err := dialCached(context.Background(), nil, countingLookup(&lookups, "9.9.9.9"), d.dial, "tcp", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if lookups != 2 {
		t.Fatalf("expected a lookup per dial, got %d", lookups)
	}
	if want := []string{"tcp 9.9.9.9:443", "tcp 9.9.9.9:443"}; !slices.Equal(d.calls, want) {
		t.Fatalf("dials = %v, want %v", d.calls, want)
	}
}

// Without DNS servers netstack cannot resolve names, so tunnelDial must resolve
// with the system resolver itself and hand netstack an IP.
func TestTunnelDialSystemDNS(t *testing.T) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tun.Close() }()
	// netstack blocks on writing packets that nothing reads
	go func() {
		bufs, sizes := [][]byte{make([]byte, 2048)}, []int{0}
		for {
			if _, err := tun.Read(bufs, sizes, 0); err != nil {
				return
			}
		}
	}()

	vt := VirtualTun{Tnet: tnet, SystemDNS: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = vt.tunnelDial(ctx, "tcp4", "localhost:80")
	if err == nil {
		t.Fatal("expected the dial through an unconnected tunnel to fail")
	}
	if strings.Contains(err.Error(), "cannot marshal DNS message") {
		t.Fatalf("hostname was resolved by netstack instead of the system resolver: %v", err)
	}
}

func TestDialCachedPassthrough(t *testing.T) {
	c, _ := newTestDNSCache(time.Minute)
	tests := []struct {
		name    string
		cache   *dnsCache
		address string
	}{
		{"ipv4 literal", c, "1.2.3.4:443"},
		{"ipv6 literal", c, "[2001:db8::1]:443"},
		{"no port", c, "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookups := 0
			d := &fakeDialer{}
			conn, err := dialCached(context.Background(), tt.cache, countingLookup(&lookups, "9.9.9.9"), d.dial, "tcp", tt.address)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if lookups != 0 {
				t.Fatalf("expected no lookup, got %d", lookups)
			}
			if want := []string{"tcp " + tt.address}; !slices.Equal(d.calls, want) {
				t.Fatalf("dials = %v, want %v", d.calls, want)
			}
		})
	}
}
