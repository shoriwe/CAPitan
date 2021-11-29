package packet

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
	"net/http"
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
	switch context.Request.FormValue("action") {
	case actions.New:
		return newCapture(mw, context)
	case actions.Import:
		break
	}
	return listCaptures(mw, context)
}

func newCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		succeed, _, captureInterfaces, _, _, getError := mw.GetUserInterfacePermissions(context.User.Username)
		if getError != nil {
			go mw.LogError(context.Request, getError)
			return false
		}
		if !succeed {
			// TODO: Log this
			return false
		}
		menuTemplate, _ := mw.Templates.ReadFile("templates/user/packet/captures/new-menu.html")
		var menu bytes.Buffer
		_ = template.Must(template.New("New Capture").Parse(string(menuTemplate))).Execute(&menu,
			struct {
				CaptureInterfaces map[string]struct{}
			}{
				CaptureInterfaces: captureInterfaces,
			},
		)
		context.Body = base.NewPage("Packet", context.NavigationBar, menu.String())
		return false
	case http.MethodConnect:
		break
	}
	return false
}
