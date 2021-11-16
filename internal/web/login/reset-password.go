package login

import (
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
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
		context.Redirect = symbols.Login
		return false
	}
	username := context.Request.PostFormValue("username")
	user, err := mw.GetUserByUsername(username)
	if err != nil {
		go mw.LogError(context.Request, err)
		context.Redirect = symbols.Login
		return false
	} else if user == nil {
		go mw.LogUserNotFound(context.Request, context.Request.PostFormValue("username"))
		context.Redirect = symbols.Login
		return false
	}
	rawTemplate, _ := mw.Templates.ReadFile("templates/login/reset-password-get-question.html")
	t := template.Must(template.New("reset-password-get_question").Parse(string(rawTemplate)))
	key, sessionCreationError := mw.ResetSessions.CreateSession(user.Username, 10*time.Minute)
	if sessionCreationError != nil {
		go mw.LogError(context.Request, sessionCreationError)
		context.Redirect = symbols.Login
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
		context.Redirect = symbols.Login
		return false
	}
	context.WriteBody = false
	return false
}

func resetPasswordAnswerQuestion(mw *middleware.Middleware, context *middleware.Context) bool {
	username := mw.ResetSessions.GetSession(context.Request.PostFormValue("key"))
	if username == "" {
		context.Redirect = symbols.Login
		return false
	}
	freshUser, freshUserSucceed := mw.LoginWithSecurityQuestion(context.Request, username, context.Request.PostFormValue("answer"))
	if !freshUserSucceed {
		context.Redirect = symbols.Login
		return false
	}
	updateSucceed := mw.ResetPassword(context.Request, username)
	if !updateSucceed {
		context.Redirect = symbols.Login
		return false
	}
	cookie, generateCookieSucceed := mw.GenerateCookieFor(context.Request, freshUser.Username)
	if !generateCookieSucceed {
		context.Redirect = symbols.Login
		return false
	}
	context.User = freshUser
	context.Redirect = symbols.Dashboard
	context.Cookie = &http.Cookie{
		Name:       symbols.CookieName,
		Value:      cookie,
		Path:       "/",
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

func resetPasswordPost(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.URL.Query().Get("action") {
	case "get-question":
		return resetPasswordGetQuestion(mw, context)
	case "answer-question":
		return resetPasswordAnswerQuestion(mw, context)
	}
	context.Redirect = symbols.Login
	return false
}

func ResetPassword(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User != nil {
		context.Redirect = symbols.Dashboard
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
