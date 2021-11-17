package web

import (
	"bytes"
	"embed"
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/logs"
	"github.com/shoriwe/CAPitan/internal/web/dashboard"
	"github.com/shoriwe/CAPitan/internal/web/login"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/settings"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
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
	cookie, getCookieError := context.Request.Cookie(symbols.CookieName)
	if getCookieError != nil {
		go mw.LogError(context.Request, getCookieError)
		return true
	}
	if cookie.Name == symbols.CookieName {
		context.SessionCookie = cookie
		user, getUserError := mw.GetUserByUsername(mw.LoginSessions.GetSession(cookie.Value))
		if getUserError != nil {
			go mw.LogError(context.Request, getUserError)
			return false
		} else if user != nil {
			if user.IsEnabled {
				if user.PasswordExpirationDate.Equal(time.Time{}) {
					context.User = user
				} else if time.Now().Before(user.PasswordExpirationDate) {
					context.User = user
				}
			}
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
		context.Redirect = symbols.Login
		return false
	}
	return true
}

func setNavigationBar(mw *middleware.Middleware, context *middleware.Context) bool {
	var navigationBar []byte
	if context.User.IsAdmin {
		navigationBar, _ = mw.Templates.ReadFile("templates/navigation-bars/admin.html")
	} else {
		navigationBar, _ = mw.Templates.ReadFile("templates/navigation-bars/user.html")
	}
	t := template.Must(template.New("navigation-bar").Parse(string(navigationBar)))
	var output bytes.Buffer
	_ = t.Execute(
		&output,
		struct {
			Username string
		}{
			Username: context.User.Username,
		},
	)
	context.NavigationBar = output.String()
	return true
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.Handle(symbols.Static, http.FileServer(http.FS(staticFS)))
	handler.HandleFunc(symbols.Login, mw.Handle(logVisit, loadCredentials, login.Login))
	handler.HandleFunc(symbols.Logout, mw.Handle(logVisit, loadCredentials, requiresLogin, login.Logout))
	handler.HandleFunc(symbols.ResetPassword, mw.Handle(logVisit, loadCredentials, login.ResetPassword))
	handler.HandleFunc(symbols.Dashboard, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, dashboard.Dashboard))
	handler.HandleFunc(symbols.Settings, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings.Settings))
	handler.HandleFunc(symbols.UpdatePassword, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings.UpdatePassword))
	handler.HandleFunc(symbols.UpdateSecurityQuestion, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings.UpdateSecurityQuestion))
	return handler
}
