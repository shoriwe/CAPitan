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
)
