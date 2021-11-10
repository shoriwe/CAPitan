package login

import (
	"fmt"
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"net/http"
)

func loginForm(mw *middleware.Middleware, context *middleware.Context, _ *http.Request) bool {
	form, _ := mw.Templates.ReadFile("templates/login/login.html")
	context.StatusCode = http.StatusOK
	context.Body = string(form)
	return false
}

func loginUser(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	username := request.PostFormValue("username")
	password := request.PostFormValue("password")
	if username == "" || password == "" {
		context.Redirect = routes.Login
		return false
	}
	user, succeed := mw.Login(request, username, password)
	if !succeed {
		context.Redirect = routes.Login
		return false
	}
	var cookie string
	cookie, succeed = mw.GenerateCookieFor(request, user)
	if !succeed {
		context.Redirect = routes.Login
		return false
	}
	context.User = user
	context.Redirect = routes.Dashboard
	context.Headers["Set-Cookie"] = fmt.Sprintf("capitan=%s", cookie)
	return false
}

func Login(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if context.User != nil {
		context.Redirect = routes.Dashboard
		return false
	}
	switch request.Method {
	case http.MethodGet:
		return loginForm(mw, context, request)
	case http.MethodPost:
		return loginUser(mw, context, request)
	}
	return http405.MethodNotAllowed(mw, context, request)
}
