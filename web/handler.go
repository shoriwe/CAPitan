package web

import (
	"embed"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web/login"
	"github.com/shoriwe/CAPitan/web/middleware"
	"net/http"
)

var (
	//go:embed static
	staticFS embed.FS

	//go:embed templates
	templatesFS embed.FS
)

func loadCredentials(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	for _, cookie := range request.Cookies() {
		if cookie.Name == "capitan" {
			context.User = mw.GetSession(cookie.Value)
			break
		}
	}
	return true
}

func logVisit(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	go mw.LogVisit(request)
	return true
}

func requiresLogin(mw *middleware.Middleware, context *middleware.Context, request *http.Request) bool {
	if context.User == nil {
		go mw.LogAuthRequired(request)
		context.StatusCode = http.StatusFound
		context.Redirect = "/login"
		return false
	}
	return true
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.Handle("/static/", http.FileServer(http.FS(staticFS)))
	handler.HandleFunc("/login", mw.Handle(logVisit, loadCredentials, login.Login))
	return handler
}
