package login

import (
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/strings"
	"net/http"
	"time"
)

func Logout(_ *middleware.Middleware, context *middleware.Context) bool {
	context.Cookie = &http.Cookie{
		Name:       strings.CookieName,
		Value:      "",
		Path:       strings.Root,
		Domain:     "",
		Expires:    time.Now(),
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}
	context.Redirect = strings.Login
	return false
}
