package web

import (
	"embed"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web/dashboard"
	"github.com/shoriwe/CAPitan/web/login"
	"github.com/shoriwe/CAPitan/web/middleware"
	navigation_bar "github.com/shoriwe/CAPitan/web/navigation-bar"
	"github.com/shoriwe/CAPitan/web/strings"
	"net/http"
	"time"
)

var (
	//go:embed static
	staticFS embed.FS

	//go:embed templates
	templatesFS embed.FS
)

func loadCredentials(mw *middleware.Middleware, context *middleware.Context) bool {
	for _, cookie := range context.Request.Cookies() {
		if cookie.Name == strings.CookieName {
			user, getUserError := mw.GetUserByUsername(mw.LoginSessions.GetSession(cookie.Value))
			if getUserError != nil {
				go mw.LogError(context.Request, getUserError)
				return false
			} else if user != nil {
				if user.PasswordExpirationDate.Equal(time.Time{}) {
					context.User = user
				} else if time.Now().Before(user.PasswordExpirationDate) && user.IsEnabled {
					context.User = user
				}
			}
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
		context.Redirect = strings.Login
		return false
	}
	return true
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.Handle("/static/", http.FileServer(http.FS(staticFS)))
	handler.HandleFunc(strings.Login, mw.Handle(logVisit, loadCredentials, login.Login))
	handler.HandleFunc(strings.Logout, mw.Handle(logVisit, loadCredentials, requiresLogin, login.Logout))
	handler.HandleFunc(strings.ResetPassword, mw.Handle(logVisit, loadCredentials, login.ResetPassword))
	handler.HandleFunc(strings.Dashboard, mw.Handle(logVisit, loadCredentials, requiresLogin, navigation_bar.SetNavigationBar, dashboard.Dashboard))
	return handler
}
