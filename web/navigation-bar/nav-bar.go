package navigation_bar

import (
	"bytes"
	"github.com/shoriwe/CAPitan/web/middleware"
	"html/template"
)

func SetNavigationBar(mw *middleware.Middleware, context *middleware.Context) bool {
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
