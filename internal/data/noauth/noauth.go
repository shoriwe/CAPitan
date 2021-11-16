package noauth

import (
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"time"
)

var admin = &objects.User{
	Id:                     1,
	Username:               "admin",
	PasswordHash:           "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
	SecurityQuestion:       "Respond this with \"admin\"",
	SecurityQuestionAnswer: "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
	IsAdmin:                true,
	IsEnabled:              true,
	PasswordExpirationDate: time.Now().Add(30 * time.Minute),
}

type NoAuth struct {
}

func (noAuth *NoAuth) GetUserByUsername(_ string) (*objects.User, error) {
	return admin, nil
}

func (noAuth *NoAuth) UpdatePasswordAndSetExpiration(_, _ string, _ time.Time) (bool, error) {
	return true, nil
}

func (noAuth *NoAuth) UpdatePassword(_, _, _ string) (bool, error) {
	return true, nil
}

func (noAuth *NoAuth) UpdateSecurityQuestion(_, _, _, _ string) (bool, error) {
	return true, nil
}

func NewNoAuthDB() data.Database {
	return &NoAuth{}
}
