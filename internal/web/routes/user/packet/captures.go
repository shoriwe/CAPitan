package packet

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
)

func listCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userCaptures := mw.ListUserCaptures(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.UserPacket
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/user/packet/captures/list.html")
	var body bytes.Buffer
	err := template.Must(template.New("Packet").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Username string
			Captures []*objects.CaptureSession
		}{
			Username: context.User.Username,
			Captures: userCaptures,
		},
	)
	if err != nil {
		context.Redirect = symbols.UserPacket
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Packet", context.NavigationBar, body.String())
	return false
}

func Captures(mw *middleware.Middleware, context *middleware.Context) bool {
	return listCaptures(mw, context)
}
