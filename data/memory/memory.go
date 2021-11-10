package memory

import (
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"golang.org/x/crypto/bcrypt"
	"sync"
	"time"
)

type Memory struct {
	*sync.Mutex
	users  map[string]*objects.User
	nextId uint
}

func (memory *Memory) GetUserByUsername(username string) (*objects.User, error) {
	memory.Lock()
	result, found := memory.users[username]
	memory.Unlock()
	if !found {
		return nil, nil
	}
	return result, nil
}

func (memory *Memory) UpdatePasswordAndSetExpiration(username, newPassword string, expiration time.Time) (bool, error) {
	memory.Lock()
	_, found := memory.users[username]
	memory.Unlock()
	if !found {
		return false, nil
	}
	newPasswordHash, generationError := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if generationError != nil {
		return false, generationError
	}
	memory.Lock()
	memory.users[username].PasswordHash = string(newPasswordHash)
	memory.users[username].PasswordExpirationDate = expiration
	memory.Unlock()
	return true, nil
}

func NewInMemoryDB() data.Database {
	result := &Memory{
		Mutex:  new(sync.Mutex),
		users:  map[string]*objects.User{},
		nextId: 2,
	}
	result.users["admin"] = &objects.User{
		Id:                     1,
		Username:               "admin",
		PasswordHash:           "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		SecurityQuestion:       "Respond this with \"admin\"",
		SecurityQuestionAnswer: "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		IsAdmin:                true,
		IsEnabled:              true,
		PasswordExpirationDate: time.Now().Add(30 * time.Minute),
	}
	return result
}
