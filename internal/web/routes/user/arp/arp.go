package arp

import (
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
)

func ARP(mw *middleware.Middleware, context *middleware.Context) bool {
	navMenu, _ := mw.Templates.ReadFile("templates/user/arp/panel.html")
	context.Body = base.NewPage("ARP", context.NavigationBar, string(navMenu))
	return false
}
