package admin

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
)

func listUsers(mw *middleware.Middleware, context *middleware.Context) bool {
	t, _ := mw.Templates.ReadFile("templates/admin/panel.html")
	users, succeed := mw.AdminListUsers(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	var listUserContents bytes.Buffer
	_ = template.Must(template.New("List Users").Parse(string(t))).Execute(
		&listUserContents,
		struct {
			Users []*objects.User
		}{
			Users: users,
		},
	)
	context.Body = base.NewPage("Admin", context.NavigationBar, listUserContents.String())
	return false
}

func Panel(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.URL.Query().Get(symbols.Action) {
	case symbols.View:
		break
	case symbols.NewUser:
		break
	case symbols.AddPacketInterface:
		break
	case symbols.DeletePacketInterface:
		break
	case symbols.AddARPInterface:
		break
	case symbols.DeleteARPInterface:
		break
	case symbols.UpdateUser:
		break
	}
	return listUsers(mw, context)
}
