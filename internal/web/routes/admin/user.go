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
		CapturedInterfaces      map[string]struct{}
		CaptureUnsetInterfaces  []string
		ARPScanInterfaces       map[string]struct{}
		ARPScanUnsetInterfaces  []string
		ARPSpoofInterfaces      map[string]struct{}
		ARPSpoofUnsetInterfaces []string
	}

	data.User = user
	data.CapturedInterfaces = captureInterfaces
	data.ARPScanInterfaces = arpScanInterfaces

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

func EditUsers(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.Request.Method == http.MethodPost {
		switch context.Request.URL.Query().Get(symbols.Action) {
		case symbols.TestUser:
			return testUser(mw, context)
		case symbols.EditUser:
			return editUser(mw, context)
		case symbols.NewUser:
			return newUser(mw, context)
		case symbols.AddPacketInterfaceToUser:
			break
		case symbols.DeletePacketInterfaceToUser:
			break
		case symbols.AddARPInterfaceToUser:
			break
		case symbols.DeleteARPInterfaceToUser:
			break
		case symbols.UpdateUser:
			break
		}
	}
	return listUsers(mw, context)
}
