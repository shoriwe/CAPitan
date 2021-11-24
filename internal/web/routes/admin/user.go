package admin

import (
	"bytes"
	"encoding/json"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
	"io"
	"net/http"
)

func listUsers(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	t, _ := mw.Templates.ReadFile("templates/admin/users.html")
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
	username := context.Request.PostFormValue(symbols.Username)
	mw.AdminCreateUser(context.Request, username)
	context.Redirect = symbols.AdminEditUsers
	return false
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
	var form struct {
		Username string
	}
	unmarshalError := json.Unmarshal(body, &form)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
	}
	found, _, getUserError := mw.GetUserByUsername(form.Username)
	if getUserError != nil {
		go mw.LogError(context.Request, getUserError)
	}
	context.Headers["Content-Type"] = "application/json"
	responseBody, _ := json.Marshal(
		struct {
			Found bool
		}{
			Found: found,
		},
	)
	context.Body = string(responseBody)
	return false
}

func editUser(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	if username == context.User.Username {
		context.Redirect = symbols.AdminEditUsers
		return false
	}
	user, captureInterfaces, arpScanInterfaces, arpSpoofInterfaces, succeed := mw.QueryUserPermissions(context.Request, username)
	if !succeed {
		context.Redirect = symbols.AdminEditUsers
		return false
	}
	var data struct {
		*objects.User
		CaptureInterfaces       map[string]struct{}
		CaptureUnsetInterfaces  []string
		ARPScanInterfaces       map[string]struct{}
		ARPScanUnsetInterfaces  []string
		ARPSpoofInterfaces      map[string]struct{}
		ARPSpoofUnsetInterfaces []string
	}

	data.User = user
	data.CaptureInterfaces = captureInterfaces
	data.ARPScanInterfaces = arpScanInterfaces
	data.ARPSpoofInterfaces = arpSpoofInterfaces

	connectedInterfaces := mw.ListNetInterfaces(context.Request)
	if connectedInterfaces == nil {
		context.Redirect = symbols.AdminEditUsers
		return false
	}

	for interfaceName := range connectedInterfaces {
		if _, found := captureInterfaces[interfaceName]; !found {
			data.CaptureUnsetInterfaces = append(data.CaptureUnsetInterfaces, interfaceName)
		}
		if _, found := arpScanInterfaces[interfaceName]; !found {
			data.ARPScanUnsetInterfaces = append(data.ARPScanUnsetInterfaces, interfaceName)
		}
		if _, found := arpSpoofInterfaces[interfaceName]; !found {
			data.ARPSpoofUnsetInterfaces = append(data.ARPSpoofUnsetInterfaces, interfaceName)
		}
	}
	rawTemplate, _ := mw.Templates.ReadFile("templates/admin/user-edit.html")
	var output bytes.Buffer
	_ = template.Must(template.New("Edit User").Parse(string(rawTemplate))).Execute(&output, data)
	context.Body = base.NewPage("Edit User", context.NavigationBar, output.String())
	return false
}

func updatePassword(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	password := context.Request.PostFormValue(symbols.Password)
	mw.AdminUpdatePassword(context.Request, username, password)
	context.Redirect = symbols.AdminPanel
	return false
}

func updateStatus(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	isAdmin := context.Request.PostFormValue(symbols.IsAdmin) == "on"
	isEnabled := context.Request.PostFormValue(symbols.IsEnabled) == "on"
	mw.AdminUpdateStatus(context.Request, username, isAdmin, isEnabled)
	context.Redirect = symbols.AdminPanel
	return false
}

func deleteARPSpoofInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminDeleteARPSpoofInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func addARPSpoofInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminAddARPSpoofInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func deleteARPScanInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminDeleteARPScanInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func addARPScanInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminAddARPScanInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func deleteCaptureInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminDeleteCaptureInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func addCaptureInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Unit test this
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	mw.AdminAddCaptureInterfacePrivilege(context.Request, username, i)
	context.Redirect = symbols.AdminPanel
	return false
}

func EditUsers(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.Request.Method == http.MethodPost {
		switch context.Request.URL.Query().Get(actions.Action) {
		case actions.TestUser:
			return testUser(mw, context)
		case actions.EditUser:
			return editUser(mw, context)
		case actions.NewUser:
			return newUser(mw, context)
		case actions.UpdatePassword:
			return updatePassword(mw, context)
		case actions.UpdateStatus:
			return updateStatus(mw, context)
		case actions.AddCaptureInterface:
			return addCaptureInterface(mw, context)
		case actions.DeleteCaptureInterface:
			return deleteCaptureInterface(mw, context)
		case actions.AddARPScanInterface:
			return addARPScanInterface(mw, context)
		case actions.DeleteARPScanInterface:
			return deleteARPScanInterface(mw, context)
		case actions.AddARPSpoofInterface:
			return addARPSpoofInterface(mw, context)
		case actions.DeleteARPSpoofInterface:
			return deleteARPSpoofInterface(mw, context)
		}
	}
	return listUsers(mw, context)
}
