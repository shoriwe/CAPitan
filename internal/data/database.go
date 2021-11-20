package data

import (
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"time"
)

type DatabaseAdminFeatures interface {
	UpdatePasswordAndSetExpiration(username, newPassword string, duration time.Duration) (bool, error)
	ListUsers(username string) ([]*objects.User, error)
}

type DatabaseGlobalFeatures interface {
	GetUserByUsername(username string) (*objects.User, error)
	UpdatePassword(username, oldPassword, newPassword string) (bool, error)
	UpdateSecurityQuestion(username, password, newQuestion, newQuestionAnswer string) (bool, error)
}

type Database interface {
	DatabaseAdminFeatures
	DatabaseGlobalFeatures
}
