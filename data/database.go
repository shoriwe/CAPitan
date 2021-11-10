package data

import (
	"github.com/shoriwe/CAPitan/data/objects"
)

type Database interface {
	GetUserByUsername(username string) (*objects.User, error)
}
