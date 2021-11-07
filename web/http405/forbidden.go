package http405

import (
	"github.com/shoriwe/CAPitan/web/middleware"
	"net/http"
)

func MethodNotAllowed(middleware *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	// TODO: Handle the method not allowed
	return false
}
