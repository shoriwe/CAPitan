package admin

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
	"net/http"
)

func listCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userCaptures := mw.AdminListAllCaptures(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/admin/packet-list.html")
	var body bytes.Buffer
	err := template.Must(template.New("Admin Packet").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Captures []*objects.CaptureSessionAdminView
		}{
			Captures: userCaptures,
		},
	)
	if err != nil {
		context.Redirect = symbols.Dashboard
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Admin Packet", context.NavigationBar, body.String())
	return false
}

func handleCaptureView(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		break
	case http.MethodPost:
		break
	}
	return http405.MethodNotAllowed(mw, context)
}

func downloadCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	username := context.Request.PostFormValue(symbols.Username)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, username, captureName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	context.ResponseWriter.Header().Add("Content-Disposition", "attachment; filename=\"capture.pcap\"")
	_, writeError := context.ResponseWriter.Write(captureSession.Pcap)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	context.WriteBody = false
	return false
}

func PacketCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.View:
		return handleCaptureView(mw, context)
	case actions.Download:
		return downloadCapture(mw, context)
	}
	return listCaptures(mw, context)
}
