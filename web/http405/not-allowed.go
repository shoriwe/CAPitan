package http405

import (
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"net/http"
)

func MethodNotAllowed(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	go mw.LogMethodNotAllowed(request)
	context.StatusCode = http.StatusOK
	context.Redirect = routes.Login
	return false
}
