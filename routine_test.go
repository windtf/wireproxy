package wireproxy

import (
	"context"
	"net"
	"regexp"
	"testing"
	"time"
)

func TestRoutedDialTimesOut(t *testing.T) {
	router := NewDomainRouter([]*regexp.Regexp{regexp.MustCompile(`^tunnel\.test$`)}, false)

	// A dial that only returns when its context ends, like an unreachable host.
	var tunnelCalls, directCalls int
	blocking := func(calls *int) dialContextFunc {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			*calls++
			if _, ok := ctx.Deadline(); !ok {
				t.Error("dial context has no deadline")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	dial := routedDial(router, 50*time.Millisecond, blocking(&tunnelCalls), blocking(&directCalls))

	for _, address := range []string{"tunnel.test:443", "direct.test:443"} {
		start := time.Now()
		_, err := dial("tcp", address)
		if err == nil {
			t.Fatalf("%s: expected an error", address)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("%s: dial took %s", address, elapsed)
		}
	}
	if tunnelCalls != 1 || directCalls != 1 {
		t.Fatalf("tunnel dialled %d times, direct %d times; want 1 each", tunnelCalls, directCalls)
	}
}
