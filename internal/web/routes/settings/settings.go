package settings

import (
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
)

func Settings(mw *middleware.Middleware, context *middleware.Context) bool {
	settingsBody, _ := mw.Templates.ReadFile("templates/settings/settings.html")
	context.Body = base.NewPage("Settings", context.NavigationBar, string(settingsBody))
	return false
}
