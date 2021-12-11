package dashboard

import (
	"fmt"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"time"
)

func Dashboard(mw *middleware.Middleware, context *middleware.Context) bool {
	var message string
	if context.User.PasswordExpirationDate.Equal(time.Time{}) {
		message = "Nothing to show here"
	} else {
		message = fmt.Sprintf("Update your password, it will expire: <b style=\"color: #e74c3c; font-family: Arial, serif;\">%s</b>", context.User.PasswordExpirationDate.Format(time.RubyDate))
	}
	rawDashboardTemplate, _ := mw.Templates.ReadFile("templates/dashboard.html")
	context.Body = base.NewPage("Dashboard", context.NavigationBar, fmt.Sprintf(string(rawDashboardTemplate), message))
	return false
}
