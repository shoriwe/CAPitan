package login

import (
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/strings"
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
		context.Redirect = strings.Login
		return false
	}
	user, succeed := mw.Login(context.Request, username, password)
	if !succeed {
		context.Redirect = strings.Login
		return false
	}
	var cookie string
	cookie, succeed = mw.GenerateCookieFor(context.Request, user.Username)
	if !succeed {
		context.Redirect = strings.Login
		return false
	}
	context.User = user
	context.Redirect = strings.Dashboard
	context.Cookie = &http.Cookie{
		Name:       strings.CookieName,
		Value:      cookie,
		Path:       strings.Root,
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
		context.Redirect = strings.Dashboard
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
