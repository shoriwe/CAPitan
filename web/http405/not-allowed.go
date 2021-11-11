package http405

import (
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/strings"
	"net/http"
)

func MethodNotAllowed(mw *middleware.Middleware, context *middleware.Context) bool {
	go mw.LogMethodNotAllowed(context.Request)
	context.StatusCode = http.StatusOK
	context.Redirect = strings.Login
	return false
}
