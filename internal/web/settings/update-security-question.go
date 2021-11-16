package settings

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
	"net/http"
)

func updateSecurityQuestionForm(mw *middleware.Middleware, context *middleware.Context) bool {
	form, _ := mw.Templates.ReadFile("templates/settings/update-security-question.html")
	var formWriter bytes.Buffer
	err := template.Must(template.New("update-security-question").Parse(string(form))).Execute(
		&formWriter, struct {
			OldQuestion string
		}{
			OldQuestion: "",
		},
	)
	if err != nil {
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Update security question", context.NavigationBar, formWriter.String())
	return false
}

func updateSecurityQuestionError(mw *middleware.Middleware, context *middleware.Context) bool {
	form, _ := mw.Templates.ReadFile("templates/settings/update-security-question-error.html")
	var formWriter bytes.Buffer
	err := template.Must(template.New("update-security-question").Parse(string(form))).Execute(
		&formWriter, struct {
			OldQuestion string
		}{
			OldQuestion: "",
		},
	)
	if err != nil {
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Update security question", context.NavigationBar, formWriter.String())
	return false
}

func updateSecurityQuestionPost(mw *middleware.Middleware, context *middleware.Context) bool {
	password := context.Request.PostFormValue("password")
	newQuestion := context.Request.PostFormValue("question")
	newQuestionAnswer := context.Request.PostFormValue("answer")
	if password == "" || newQuestion == "" || newQuestionAnswer == "" {
		context.Redirect = symbols.UpdateSecurityQuestion
		return false
	}
	if mw.UpdateSecurityQuestion(context.Request, context.User.Username, password, newQuestion, newQuestionAnswer) {
		context.Redirect = symbols.Settings
		return false
	}
	return updateSecurityQuestionError(mw, context)
}

func UpdateSecurityQuestion(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		return updateSecurityQuestionForm(mw, context)
	case http.MethodPost:
		return updateSecurityQuestionPost(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}
