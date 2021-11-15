package settings

import (
	"github.com/shoriwe/CAPitan/web/base"
	"github.com/shoriwe/CAPitan/web/middleware"
)

func Settings(mw *middleware.Middleware, context *middleware.Context) bool {
	settingsBody, _ := mw.Templates.ReadFile("templates/settings.html")
	context.Body = base.NewPage("Dashboard", context.NavigationBar, string(settingsBody))
	return false
}
