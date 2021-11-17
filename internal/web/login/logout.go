package login

import (
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
)

func Logout(mw *middleware.Middleware, context *middleware.Context) bool {
	mw.LoginSessions.Remove(context.SessionCookie.Value)
	context.NewCookie = &http.Cookie{
		Name:  symbols.CookieName,
		Value: "",
	}
	context.Redirect = symbols.Login
	return false
}
