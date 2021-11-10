package data

import (
	"github.com/shoriwe/CAPitan/data/objects"
	"time"
)

type DatabaseAdminFeatures interface {
	UpdatePasswordAndSetExpiration(username, newPassword string, expiration time.Time) (bool, error)
}

type DatabaseGlobalFeatures interface {
	GetUserByUsername(username string) (*objects.User, error)
}

type Database interface {
	DatabaseAdminFeatures
	DatabaseGlobalFeatures
}
