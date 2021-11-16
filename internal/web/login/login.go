package login

import (
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
	"time"
)

func loginForm(mw *middleware.Middleware, context *middleware.Context) bool {
	form, _ := mw.Templates.ReadFile("templates/login/login.html")
	context.StatusCode = http.StatusOK
	context.Body = string(form)
	return false
}

func loginUser(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue("username")
	password := context.Request.PostFormValue("password")
	if username == "" || password == "" {
		context.Redirect = symbols.Login
		return false
	}
	user, succeed := mw.Login(context.Request, username, password)
	if !succeed {
		context.Redirect = symbols.Login
		return false
	}
	var cookie string
	cookie, succeed = mw.GenerateCookieFor(context.Request, user.Username)
	if !succeed {
		context.Redirect = symbols.Login
		return false
	}
	context.User = user
	context.Redirect = symbols.Dashboard
	context.Cookie = &http.Cookie{
		Name:       symbols.CookieName,
		Value:      cookie,
		Path:       symbols.Root,
		Domain:     "",
		Expires:    time.Now().Add(24 * time.Hour),
		RawExpires: "",
		MaxAge:     0,
		Secure:     true,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}
	return false
}

func Login(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User != nil {
		context.Redirect = symbols.Dashboard
		return false
	}
	switch context.Request.Method {
	case http.MethodGet:
		return loginForm(mw, context)
	case http.MethodPost:
		return loginUser(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}
