package login

import (
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
	"time"
)

func Logout(mw *middleware.Middleware, context *middleware.Context) bool {
	mw.LoginSessions.Remove(context.Cookie.Value)
	context.Cookie = &http.Cookie{
		Name:    symbols.CookieName,
		Value:   "",
		Path:    symbols.Root,
		Expires: time.Time{},
	}
	context.Redirect = symbols.Login
	return false
}
