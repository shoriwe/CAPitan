package packet

import (
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
)

func downloadCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, context.User.Username, captureName)
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
