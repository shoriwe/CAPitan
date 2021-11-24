package admin

import (
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
)

func Panel(mw *middleware.Middleware, context *middleware.Context) bool {
	settingsBody, _ := mw.Templates.ReadFile("templates/admin/panel.html")
	context.Body = base.NewPage("Admin", context.NavigationBar, string(settingsBody))
	return false
}
