package memory

import (
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"time"
)

type Memory struct {
	users  map[string]*objects.User
	nextId uint
}

func (memory *Memory) GetUserByUsername(username string) (*objects.User, error) {
	result, found := memory.users[username]
	if !found {
		return nil, nil
	}
	return result, nil
}

func NewInMemoryDB() data.Database {
	result := &Memory{
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
