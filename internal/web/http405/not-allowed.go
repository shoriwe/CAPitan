package http405

import (
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
)

func MethodNotAllowed(mw *middleware.Middleware, context *middleware.Context) bool {
	go mw.LogMethodNotAllowed(context.Request)
	context.StatusCode = http.StatusOK
	context.Redirect = symbols.Login
	return false
}
