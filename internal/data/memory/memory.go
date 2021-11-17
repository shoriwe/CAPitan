package memory

import (
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/objects"
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
	if found {
		return result, nil
	}
	return nil, nil
}

func (memory *Memory) UpdatePasswordAndSetExpiration(username, newPassword string, duration time.Duration) (bool, error) {
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
	memory.users[username].PasswordExpirationDate = time.Now().Add(duration)
	memory.Unlock()
	return true, nil
}

func (memory *Memory) UpdatePassword(username, oldPassword, newPassword string) (bool, error) {
	memory.Lock()
	user, found := memory.users[username]
	memory.Unlock()
	if !found {
		return false, nil
	}
	compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if compareError != nil {
		if compareError == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, compareError
	}
	newPasswordHash, generateError := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if generateError != nil {
		return false, generateError
	}
	memory.Lock()
	memory.users[username].PasswordHash = string(newPasswordHash)
	memory.users[username].PasswordExpirationDate = time.Time{}
	memory.Unlock()
	return true, nil
}

func (memory *Memory) UpdateSecurityQuestion(username, password, newQuestion, newQuestionAnswer string) (bool, error) {
	memory.Lock()
	user, found := memory.users[username]
	memory.Unlock()
	if !found {
		return false, nil
	}
	compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if compareError != nil {
		if compareError == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, compareError
	}
	newQuestionAnswerHash, generateError := bcrypt.GenerateFromPassword([]byte(newQuestionAnswer), bcrypt.DefaultCost)
	if generateError != nil {
		return false, generateError
	}
	memory.Lock()
	memory.users[username].SecurityQuestion = newQuestion
	memory.users[username].SecurityQuestionAnswer = string(newQuestionAnswerHash)
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
