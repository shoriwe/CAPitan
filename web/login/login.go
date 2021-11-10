package login

import (
	"fmt"
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"net/http"
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
		context.Redirect = routes.Login
		return false
	}
	user, succeed := mw.Login(context.Request, username, password)
	if !succeed {
		context.Redirect = routes.Login
		return false
	}
	var cookie string
	cookie, succeed = mw.GenerateCookieFor(context.Request, user)
	if !succeed {
		context.Redirect = routes.Login
		return false
	}
	context.User = user
	context.Redirect = routes.Dashboard
	context.Headers["Set-Cookie"] = fmt.Sprintf("capitan=%s", cookie)
	return false
}

func Login(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User != nil {
		context.Redirect = routes.Dashboard
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
