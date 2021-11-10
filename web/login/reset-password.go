package login

import (
	"fmt"
	"github.com/shoriwe/CAPitan/web/http405"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"html/template"
	"net/http"
	"time"
)

func resetPasswordGet(mw *middleware.Middleware, context *middleware.Context) bool {
	result, _ := mw.Templates.ReadFile("templates/login/reset-password.html")
	context.StatusCode = http.StatusOK
	context.Body = string(result)
	return false
}

func resetPasswordGetQuestion(mw *middleware.Middleware, context *middleware.Context) bool {
	if !mw.Limit(context.Request) {
		context.Redirect = routes.Login
		return false
	}
	username := context.Request.PostFormValue("username")
	user, err := mw.GetUserByUsername(username)
	if err != nil {
		go mw.LogError(context.Request, err)
		context.Redirect = routes.Login
		return false
	} else if user == nil {
		go mw.LogUserNotFound(context.Request, context.Request.PostFormValue("username"))
		context.Redirect = routes.Login
		return false
	}
	rawTemplate, _ := mw.Templates.ReadFile("templates/login/reset-password-get-question.html")
	t := template.Must(template.New("reset-password-get_question").Parse(string(rawTemplate)))
	key, sessionCreationError := mw.ResetSessions.CreateSession(user, 10*time.Minute)
	if sessionCreationError != nil {
		go mw.LogError(context.Request, sessionCreationError)
		context.Redirect = routes.Login
		return false
	}
	executeError := t.Execute(context.ResponseWriter, struct {
		Username         string
		SecurityQuestion string
		Key              string
	}{
		user.Username,
		user.SecurityQuestion,
		key,
	})
	if executeError != nil {
		go mw.LogError(context.Request, executeError)
		context.Redirect = routes.Login
		return false
	}
	context.WriteBody = false
	return false
}

func resetPasswordAnswerQuestion(mw *middleware.Middleware, context *middleware.Context) bool {
	user := mw.ResetSessions.GetSession(context.Request.PostFormValue("key"))
	if user == nil {
		context.Redirect = routes.Login
		return false
	}
	freshUser, freshUserSucceed := mw.LoginWithSecurityQuestion(context.Request, user.Username, context.Request.PostFormValue("answer"))
	if freshUserSucceed {
		updateSucceed := mw.ResetPassword(context.Request, user.Username)
		if updateSucceed {
			cookie, generateCookieSucceed := mw.GenerateCookieFor(context.Request, freshUser)
			if generateCookieSucceed {
				context.Headers["Set-Cookie"] = fmt.Sprintf("capitan=%s", cookie)
				context.Redirect = routes.Dashboard
				return false
			}
		}
	}
	context.Redirect = routes.Login
	return false
}

func resetPasswordPost(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.URL.Query().Get("action") {
	case "get-question":
		return resetPasswordGetQuestion(mw, context)
	case "answer-question":
		return resetPasswordAnswerQuestion(mw, context)
	}
	context.Redirect = routes.Login
	return false
}

func ResetPassword(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User != nil {
		context.Redirect = routes.Dashboard
		return false
	}
	switch context.Request.Method {
	case http.MethodGet:
		return resetPasswordGet(mw, context)
	case http.MethodPost:
		return resetPasswordPost(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}
