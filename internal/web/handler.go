package web

import (
	"bytes"
	"embed"
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/memory"
	"github.com/shoriwe/CAPitan/internal/logs"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/routes/admin"
	"github.com/shoriwe/CAPitan/internal/web/routes/dashboard"
	login2 "github.com/shoriwe/CAPitan/internal/web/routes/login"
	settings2 "github.com/shoriwe/CAPitan/internal/web/routes/settings"
	"github.com/shoriwe/CAPitan/internal/web/routes/user/arp"
	"github.com/shoriwe/CAPitan/internal/web/routes/user/arp/scan"
	"github.com/shoriwe/CAPitan/internal/web/routes/user/arp/spoof"
	"github.com/shoriwe/CAPitan/internal/web/routes/user/packet"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html"
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
		found, user, getUserError := mw.GetUserByUsername(mw.LoginSessions.GetSession(cookie.Value))
		if getUserError != nil {
			go mw.LogError(context.Request, getUserError)
			return false
		} else if found {
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

func requiresAdminPrivilege(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.User.IsAdmin {
		return true
	}
	go mw.LogAdminRequired(context.Request, context.User.Username)
	context.Redirect = symbols.Dashboard
	return false
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
			Username: html.EscapeString(context.User.Username),
		},
	)
	context.NavigationBar = output.String()
	return true
}

func redirectToLogin(mw *middleware.Middleware, context *middleware.Context) bool {
	context.Redirect = symbols.Login
	return false
}

func NewServerMux(database data.Database, logger *logs.Logger) http.Handler {
	mw := middleware.New(database, logger, templatesFS)
	handler := http.NewServeMux()
	handler.HandleFunc(symbols.Favicon,
		mw.Handle(
			func(mw *middleware.Middleware, context *middleware.Context) bool {
				context.Redirect = "/static/images/favicon.ico"
				return false
			},
		),
	)
	// The most important: Redirect the index.html to login.html
	handler.HandleFunc("/", mw.Handle(logVisit, loadCredentials, redirectToLogin))
	handler.HandleFunc("/index.html", mw.Handle(logVisit, loadCredentials, redirectToLogin))
	// Anyone
	handler.Handle(symbols.Static, http.FileServer(http.FS(staticFS)))
	handler.HandleFunc(symbols.Login, mw.Handle(logVisit, loadCredentials, login2.Login))
	handler.HandleFunc(symbols.Logout, mw.Handle(logVisit, loadCredentials, requiresLogin, login2.Logout))
	handler.HandleFunc(symbols.ResetPassword, mw.Handle(logVisit, loadCredentials, login2.ResetPassword))
	// Any loged user
	handler.HandleFunc(symbols.Dashboard, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, dashboard.Dashboard))
	handler.HandleFunc(symbols.Settings, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings2.Settings))
	handler.HandleFunc(symbols.UpdatePassword, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings2.UpdatePassword))
	handler.HandleFunc(symbols.UpdateSecurityQuestion, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, settings2.UpdateSecurityQuestion))
	// Admin
	handler.HandleFunc(symbols.AdminPanel, mw.Handle(logVisit, loadCredentials, requiresLogin, requiresAdminPrivilege, setNavigationBar, admin.Panel))
	handler.HandleFunc(symbols.AdminEditUsers, mw.Handle(logVisit, loadCredentials, requiresLogin, requiresAdminPrivilege, setNavigationBar, admin.EditUsers))
	handler.HandleFunc(symbols.AdminARPScans, mw.Handle(logVisit, loadCredentials, requiresLogin, requiresAdminPrivilege, setNavigationBar, admin.ListUserARPScans))
	handler.HandleFunc(symbols.AdminPacketCaptures, mw.Handle(logVisit, loadCredentials, requiresLogin, requiresAdminPrivilege, setNavigationBar, admin.PacketCaptures))
	// User
	handler.HandleFunc(symbols.UserPacketCaptures, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, packet.Captures))
	handler.HandleFunc(symbols.UserARP, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, arp.ARP))
	handler.HandleFunc(symbols.UserARPSpoof, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, spoof.ARPSpoof))
	handler.HandleFunc(symbols.UserARPScan, mw.Handle(logVisit, loadCredentials, requiresLogin, setNavigationBar, scan.ARPScan))

	if _, ok := database.(*memory.Memory); ok {
		request, _ := http.NewRequest(http.MethodGet, "/", nil)
		for netInterface := range mw.ListNetInterfaces(request) {
			mw.AdminAddCaptureInterfacePrivilege(request, "admin", netInterface)
			mw.AdminAddARPScanInterfacePrivilege(request, "admin", netInterface)
			mw.AdminAddARPSpoofInterfacePrivilege(request, "admin", netInterface)
		}
	}
	return handler
}
