// Package sessions — простое in-memory хранилище сессий (cookie-based).
package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session — данные сессии.
type Session struct {
	Token      string
	Username   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Store — хранилище сессий.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
}

// New создаёт хранилище сессий с TTL по умолчанию 12 часов.
func New() *Store {
	return &Store{
		sessions: map[string]*Session{},
		ttl:      12 * time.Hour,
	}
}

// Create создаёт новую сессию для пользователя.
func (s *Store) Create(username string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := generateToken()
	sess := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.sessions[token] = sess
	s.cleanup()
	return sess
}

// Get возвращает username по токену (пустая строка если не найдено/истекло).
func (s *Store) Get(token string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, token)
		return ""
	}
	return sess.Username
}

// Delete удаляет сессию (logout).
func (s *Store) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *Store) cleanup() {
	now := time.Now()
	for token, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
