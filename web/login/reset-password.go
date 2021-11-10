package login

import (
	"fmt"
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"net/http"
)

func resetPasswordGet(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	result, _ := mw.Templates.ReadFile("templates/login/reset-password.html")
	context.StatusCode = http.StatusOK
	context.Body = string(result)
	return false
}

func resetPasswordGetQuestion(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if !mw.Limit(request) {
		context.Redirect = routes.Login
		return false
	}
	username := request.PostFormValue("username")
	user, err := mw.GetUserByUsername(username)
	if err != nil {
		go mw.LogError(request, err)
		context.Redirect = routes.Login
		return false
	} else if user == nil {
		go mw.LogUserNotFound(request, request.PostFormValue("username"))
		context.Redirect = routes.Login
		return false
	}
	fmt.Println("HERE")
	// TODO: Prepare the answer question form
	return false
}

func resetPasswordPost(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	switch request.URL.Query().Get("action") {
	case "get-question":
		return resetPasswordGetQuestion(mw, context, request)
	case "answer-question":
		break
	}
	return false
}

func ResetPassword(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if context.User != nil {
		context.Redirect = routes.Dashboard
		return false
	}
	switch request.Method {
	case http.MethodGet:
		return resetPasswordGet(mw, context, request)
	case http.MethodPost:
		return resetPasswordPost(mw, context, request)
	}
	return http405.MethodNotAllowed(mw, context, request)
}
