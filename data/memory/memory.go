package memory

import (
	"crypto/sha512"
	"encoding/hex"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"time"
)

type Memory struct {
	users map[string]*objects.User
}

func (memory *Memory) Login(username, password string) (*objects.User, error) {
	result, found := memory.users[username]
	if !found {
		return nil, nil
	}
	p := sha512.New()
	p.Write([]byte(password))
	passwordHash := p.Sum(nil)
	if hex.EncodeToString(passwordHash) == result.PasswordHash {
		return result, nil
	}
	return nil, nil
}

func NewInMemoryDB() data.Database {
	result := &Memory{
		users: map[string]*objects.User{},
	}
	result.users["admin"] = &objects.User{
		Id:                     1,
		Username:               "admin",
		PasswordHash:           "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec",
		SecurityQuestion:       "Respond this with \"admin\"",
		SecurityQuestionAnswer: "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec",
		IsAdmin:                true,
		IsEnabled:              true,
		PasswordExpirationDate: time.Now().Add(24 * time.Hour),
	}
	return result
}
