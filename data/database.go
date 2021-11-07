package data

import "github.com/shoriwe/CAPitan/data/objects"

type Database interface {
	Login(username, password string) (*objects.User, error)
}
