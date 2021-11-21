package admin

import (
	"bytes"
	"encoding/json"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
	"io"
	"net/http"
)

func listUsers(mw *middleware.Middleware, context *middleware.Context) bool {
	t, _ := mw.Templates.ReadFile("templates/admin/panel.html")
	users, succeed := mw.AdminListUsers(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	var listUserContents bytes.Buffer
	_ = template.Must(template.New("List Users").Parse(string(t))).Execute(
		&listUserContents,
		struct {
			Users []*objects.User
		}{
			Users: users,
		},
	)
	context.Body = base.NewPage("Admin", context.NavigationBar, listUserContents.String())
	return false
}

func newUser(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue("username")
	mw.AdminCreateUser(context.Request, username)
	context.Redirect = symbols.AdminPanel
	return false
}

type testUserForm struct {
	Username string
}

func testUser(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	if context.Request.Header.Get("Content-Type") != "application/json" {
		return false
	}
	body, readError := io.ReadAll(context.Request.Body)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		return false
	}
	var form testUserForm
	unmarshalError := json.Unmarshal(body, &form)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
	}
	user, getUserError := mw.GetUserByUsername(form.Username)
	if getUserError != nil {
		go mw.LogError(context.Request, getUserError)
	}
	context.Headers["Content-Type"] = "application/json"
	responseBody, _ := json.Marshal(
		struct {
			Found bool
		}{
			Found: user != nil,
		},
	)
	context.Body = string(responseBody)
	return false
}

func Panel(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.Request.Method == http.MethodPost {
		switch context.Request.URL.Query().Get(symbols.Action) {
		case symbols.TestUser:
			return testUser(mw, context)
		case symbols.View:
			break
		case symbols.NewUser:
			return newUser(mw, context)
		case symbols.AddPacketInterface:
			break
		case symbols.DeletePacketInterface:
			break
		case symbols.AddARPInterface:
			break
		case symbols.DeleteARPInterface:
			break
		case symbols.UpdateUser:
			break
		}
	}
	return listUsers(mw, context)
}
