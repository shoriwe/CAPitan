package dashboard

import (
	"fmt"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"time"
)

var (
	dashboardTemplate = `<link href="/static/css/dashboard.css" rel="stylesheet" type="text/css">
<div class="dashboard-container">
	<h1 style="color: black;" class="dashboard-message">%s</h1>
<div>`
)

func Dashboard(mw *middleware.Middleware, context *middleware.Context) bool {
	var message string
	if context.User.PasswordExpirationDate.Equal(time.Time{}) {
		message = "Nothing to show here"
	} else {
		message = fmt.Sprintf("Update your password, it will expire: <b style=\"color: #e74c3c;\">%s</b>", context.User.PasswordExpirationDate.Format(time.RubyDate))
	}
	context.Body = base.NewPage("Dashboard", context.NavigationBar, fmt.Sprintf(dashboardTemplate, message))
	return false
}
