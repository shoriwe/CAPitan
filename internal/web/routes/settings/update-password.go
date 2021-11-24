package settings

import (
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
)

func updatePasswordForm(mw *middleware.Middleware, context *middleware.Context) bool {
	form, _ := mw.Templates.ReadFile("templates/settings/update-password.html")
	context.Body = base.NewPage("Update password", context.NavigationBar, string(form))
	return false
}

func updatePasswordError(mw *middleware.Middleware, context *middleware.Context) bool {
	form, _ := mw.Templates.ReadFile("templates/settings/update-password-error.html")
	context.Body = base.NewPage("Update password", context.NavigationBar, string(form))
	return false
}

func updatePasswordPost(mw *middleware.Middleware, context *middleware.Context) bool {
	old := context.Request.PostFormValue(symbols.Old)
	newPassword := context.Request.PostFormValue(symbols.New)
	confirmation := context.Request.PostFormValue(symbols.Confirmation)
	if old == "" || newPassword == "" || confirmation == "" {
		context.Redirect = symbols.UpdatePassword
		return false
	}
	if mw.UpdatePassword(context.Request, context.User.Username, old, newPassword, confirmation) {
		context.Redirect = symbols.Settings
		return false
	}
	return updatePasswordError(mw, context)
}

func UpdatePassword(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		return updatePasswordForm(mw, context)
	case http.MethodPost:
		return updatePasswordPost(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}
