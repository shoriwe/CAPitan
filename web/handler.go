package web

import (
	"embed"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web/login"
	"github.com/shoriwe/CAPitan/web/middleware"
	"github.com/shoriwe/CAPitan/web/routes"
	"net/http"
)

var (
	//go:embed static
	staticFS embed.FS

	//go:embed templates
	templatesFS embed.FS
)

func loadCredentials(mw *middleware.Middleware, context *middleware.Context) bool {
	for _, cookie := range context.Request.Cookies() {
		if cookie.Name == "capitan" {
			context.User = mw.LoginSessions.GetSession(cookie.Value)
			break
		}
	}
	return true
}

func logVisit(mw *middleware.Middleware, context *middleware.Context) bool {
	go mw.LogVisit(context.Request)
	return true
}

func requiresLogin(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User == nil {
		go mw.LogAuthRequired(context.Request)
		context.Redirect = routes.Login
		return false
	}
	return true
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.Handle("/static/", http.FileServer(http.FS(staticFS)))
	handler.HandleFunc(routes.Login, mw.Handle(logVisit, loadCredentials, login.Login))
	handler.HandleFunc(routes.ResetPassword, mw.Handle(logVisit, loadCredentials, login.ResetPassword))
	return handler
}
