package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// Session represents a pending connection session
type Session struct {
	PubKey   string    `json:"pubkey"`
	Endpoint string    `json:"endpoint"`
	TunnelIP string    `json:"tunnel_ip"`
	Created  time.Time `json:"-"`
}

// Store holds pending sessions
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session // code -> session
}

func NewStore() *Store {
	s := &Store{
		sessions: make(map[string]*Session),
	}
	// Cleanup old sessions every minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			s.cleanup()
		}
	}()
	return s
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for code, session := range s.sessions {
		if now.Sub(session.Created) > 5*time.Minute {
			delete(s.sessions, code)
		}
	}
}

func (s *Store) Get(code string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[code]
}

func (s *Store) Set(code string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session.Created = time.Now()
	s.sessions[code] = session
}

func (s *Store) Delete(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, code)
}

type SessionRequest struct {
	Code     string `json:"code"`
	PubKey   string `json:"pubkey"`
	Endpoint string `json:"endpoint"`
	TunnelIP string `json:"tunnel_ip"`
}

func main() {
	store := NewStore()

	http.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		var req SessionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Code == "" {
			http.Error(w, "Code is required", http.StatusBadRequest)
			return
		}

		// Check if peer already registered
		existingPeer := store.Get(req.Code)
		if existingPeer != nil {
			// Peer exists, return their info and delete the session
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(existingPeer)
			store.Delete(req.Code)
			return
		}

		// No peer yet, store our info and wait
		store.Set(req.Code, &Session{
			PubKey:   req.PubKey,
			Endpoint: req.Endpoint,
			TunnelIP: req.TunnelIP,
		})

		// Return 202 Accepted - peer hasn't connected yet
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "waiting"}`))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	println("Rendezvous server listening on :8080")
	http.ListenAndServe(":8080", nil)
}
