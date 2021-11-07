package web

import (
	"embed"
	"fmt"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web/login"
	"github.com/shoriwe/CAPitan/web/middleware"
	"net/http"
)

var (
	//go:embed css
	staticFS embed.FS

	//go:embed templates
	templatesFS embed.FS
)

func loadCredentials(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	// TODO: Check if the cookies are valid and load the user object in the context
	fmt.Println(request.Cookies())
	return true
}

func logVisit(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	mw.LogVisit(request)
	return true
}

func requiresLogin(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if context.User == nil {
		// TODO: Log no login tried request
		// TODO: Redirect to login page
		return false
	}
	return true
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	handler.HandleFunc("/login", mw.Handle(logVisit, loadCredentials, login.Login))
	return handler
}
