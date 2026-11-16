package wireproxy

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// SpawnRoutine spawns a UDP listener on the WireGuard side and forwards each
// remote peer to the configured local target.
// Flow: <WireGuard peer> --(wireguard)--> ListenPort --> Target (local network)
func (conf *UDPServerTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	target, err := net.ResolveUDPAddr("udp", conf.Target)
	if err != nil {
		log.Fatalf("UDPServerTunnel: could not resolve target %s: %v", conf.Target, err)
	}

	var addrs []net.IP
	if vt.Conf != nil {
		for _, addr := range vt.Conf.Endpoint {
			addrs = append(addrs, net.IP(addr.AsSlice()))
		}
	}
	if len(addrs) == 0 {
		log.Fatal("UDPServerTunnel: no WireGuard interface address configured")
	}

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second

	started := 0
	for _, addr := range addrs {
		listener, err := vt.Tnet.ListenUDP(&net.UDPAddr{IP: addr, Port: conf.ListenPort})
		if err != nil {
			errorLogger.Printf("UDPServerTunnel: could not listen on WireGuard address %s port %d: %v", addr, conf.ListenPort, err)
			continue
		}

		started++
		log.Printf("UDPServerTunnel listening on %s, forwarding to %s", listener.LocalAddr(), conf.Target)
		go serveUDPServerTunnel(listener, target, inactivityDur)
	}

	if started == 0 {
		log.Fatal("UDPServerTunnel: could not listen on any WireGuard interface address")
	}
}

// serveUDPServerTunnel relays datagrams between WireGuard peers and a local
// target. Each remote peer owns one connected local UDP socket so replies can
// be matched back to the correct peer.
func serveUDPServerTunnel(listener net.PacketConn, target *net.UDPAddr, inactivityDur time.Duration) {
	sessions := make(map[string]*udpSession)
	var sessionMu sync.Mutex
	done := make(chan struct{})

	removeSession := func(key string, sess *udpSession) {
		sessionMu.Lock()
		if current, ok := sessions[key]; ok && current == sess {
			current.close()
			delete(sessions, key)
		}
		sessionMu.Unlock()
	}

	defer func() {
		close(done)
		sessionMu.Lock()
		for key, sess := range sessions {
			sess.close()
			delete(sessions, key)
		}
		sessionMu.Unlock()
	}()

	if inactivityDur > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
				}

				now := time.Now()
				sessionMu.Lock()
				for key, sess := range sessions {
					if sess.inactive(now) {
						log.Printf("UDPServerTunnel: closing inactive session for %s", key)
						sess.close()
						delete(sessions, key)
					}
				}
				sessionMu.Unlock()
			}
		}()
	}

	buf := make([]byte, 64*1024)
	for {
		n, src, err := listener.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			errorLogger.Printf("UDPServerTunnel: error reading from WireGuard: %v", err)
			continue
		}

		key := src.String()

		sessionMu.Lock()
		sess := sessions[key]
		sessionMu.Unlock()

		if sess == nil {
			localConn, err := net.DialUDP("udp", nil, target)
			if err != nil {
				errorLogger.Printf("UDPServerTunnel: could not dial target %s: %v", target, err)
				continue
			}

			sess = &udpSession{
				remoteConn:    localConn,
				lastActive:    time.Now(),
				closeChan:     make(chan struct{}),
				inactivityDur: inactivityDur,
			}

			sessionMu.Lock()
			sessions[key] = sess
			sessionMu.Unlock()

			go forwardRemoteToPeer(listener, src, sess, func() {
				removeSession(key, sess)
			})
		} else {
			sess.touch()
		}

		if _, err := sess.remoteConn.Write(buf[:n]); err != nil {
			errorLogger.Printf("UDPServerTunnel: could not write to target %s: %v", target, err)
			removeSession(key, sess)
		}
	}
}
