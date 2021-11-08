package http405

import (
	"github.com/shoriwe/CAPitan/web/middleware"
	"net/http"
)

func MethodNotAllowed(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	go mw.LogMethodNotAllowed(request)
	context.StatusCode = http.StatusOK
	context.Redirect = "/login"
	return false
}
