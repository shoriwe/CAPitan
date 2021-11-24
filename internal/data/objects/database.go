package objects

import "time"

type (
	User struct {
		Id                     uint
		Username               string
		PasswordHash           string
		SecurityQuestion       string
		SecurityQuestionAnswer string
		IsAdmin                bool
		IsEnabled              bool
		PasswordExpirationDate time.Time
	}
	ARPSpoofPermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
	ARPScanPermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
	CapturePermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
)
