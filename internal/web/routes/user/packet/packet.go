package packet

import (
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
)

func Panel(mw *middleware.Middleware, context *middleware.Context) bool {
	navMenu, _ := mw.Templates.ReadFile("templates/user/packet/panel.html")
	context.Body = base.NewPage("Packet", context.NavigationBar, string(navMenu))
	return false
}