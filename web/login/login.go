package login

import (
	"fmt"
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"net/http"
)

func loginForm(middleware *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	form, _ := middleware.Templates.ReadFile("templates/login/login.html")
	context.StatusCode = http.StatusOK
	context.Body = string(form)
	return false
}

func loginUser(middleware *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if !request.PostForm.Has("username") || !request.PostForm.Has("password") {
		return loginForm(middleware, context, request)
	}
	username := request.PostForm.Get("username")
	password := request.PostForm.Get("password")
	/*
		TODO: Check credentials
		TODO: On fail, reload the login page
		TODO: On success, set cookies and redirect to dashboard
	*/
	user, succeed := middleware.Login(request, username, password)
	if !succeed {
		// TODO: Reload login page but with the message
		return false
	}
	// TODO: Set cookies
	// TODO: Redirect to dashboard
	fmt.Println(user)
	return false
}

func Login(middleware *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if context.User != nil {
		context.StatusCode = http.StatusOK
		context.Body = `<script>window.location = "/dashboard";</script>`
		return false
	}
	switch request.Method {
	case http.MethodGet:
		return loginForm(middleware, context, request)
	case http.MethodPost:
		return loginUser(middleware, context, request)
	}
	return http405.MethodNotAllowed(middleware, context, request)
}
