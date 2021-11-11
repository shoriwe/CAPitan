package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type session struct {
	username   string
	registered time.Time
	available  time.Duration
}

type Sessions struct {
	*sync.Mutex
	sessions map[string]session
}

func (sessions *Sessions) GetSession(key string) string {
	result, found := sessions.sessions[key]
	if !found {
		return ""
	}
	return result.username
}

func (sessions *Sessions) CreateSession(username string, available time.Duration) (string, error) {
	rawKey := make([]byte, 32)
	_, readError := rand.Read(rawKey)
	if readError != nil {
		return "", readError
	}
	key := hex.EncodeToString(rawKey)
	value := session{
		username:   username,
		registered: time.Now(),
		available:  available,
	}
	sessions.Lock()
	sessions.sessions[key] = value
	sessions.Unlock()
	return key, nil
}

func NewSessions() *Sessions {
	result := &Sessions{
		Mutex:    new(sync.Mutex),
		sessions: map[string]session{},
	}
	go func(session *Sessions) {
		for {
			time.Sleep(30 * time.Minute)
			session.Lock()
			for key, value := range session.sessions {
				if time.Now().After(value.registered.Add(value.available)) {
					delete(session.sessions, key)
				}
			}
			session.Unlock()
		}
	}(result)
	return result
}
