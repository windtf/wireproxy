package wireproxy

import (
	"net"
	"testing"
)

func TestUDPSessionCloseIsIdempotent(t *testing.T) {
	local, remote := net.Pipe()
	session := &udpSession{
		remoteConn: local,
		closeChan:  make(chan struct{}),
	}

	session.close()
	session.close()

	select {
	case <-session.closeChan:
	default:
		t.Fatal("session close channel was not closed")
	}

	if _, err := remote.Write([]byte("data")); err == nil {
		t.Fatal("remote connection remained open after session close")
	}
	_ = remote.Close()
}
