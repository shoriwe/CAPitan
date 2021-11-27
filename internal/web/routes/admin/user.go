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

type succeedResponse struct {
	Succeed bool
}

type interfaceInformation struct {
	Name    string
	Address string
}

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
	username := context.Request.PostFormValue(symbols.Username)
	succeed := mw.AdminCreateUser(context.Request, username)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func testUser(mw *middleware.Middleware, context *middleware.Context) bool {
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
	context.Headers["Content-Type"] = "application/json"
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
		CaptureInterfaces       []interfaceInformation
		CaptureUnsetInterfaces  []interfaceInformation
		ARPScanInterfaces       []interfaceInformation
		ARPScanUnsetInterfaces  []interfaceInformation
		ARPSpoofInterfaces      []interfaceInformation
		ARPSpoofUnsetInterfaces []interfaceInformation
	}

	data.User = user

	connectedInterfaces := mw.ListNetInterfaces(context.Request)
	if connectedInterfaces == nil {
		context.Redirect = symbols.AdminEditUsers
		return false
	}

	for interfaceName, networkInterface := range connectedInterfaces {
		var iAddress string
		for _, address := range networkInterface.Addresses {
			iAddress = address.IP.String()
		}
		information := interfaceInformation{
			Name:    interfaceName,
			Address: iAddress,
		}
		if _, found := captureInterfaces[interfaceName]; !found {
			data.CaptureUnsetInterfaces = append(data.CaptureUnsetInterfaces, information)
		} else {
			data.CaptureInterfaces = append(data.CaptureInterfaces, information)
		}
		if _, found := arpScanInterfaces[interfaceName]; !found {
			data.ARPScanUnsetInterfaces = append(data.ARPScanUnsetInterfaces, information)
		} else {
			data.ARPScanInterfaces = append(data.ARPScanInterfaces, information)
		}
		if _, found := arpSpoofInterfaces[interfaceName]; !found {
			data.ARPSpoofUnsetInterfaces = append(data.ARPSpoofUnsetInterfaces, information)
		} else {
			data.ARPSpoofInterfaces = append(data.ARPSpoofInterfaces, information)
		}
	}
	rawTemplate, _ := mw.Templates.ReadFile("templates/admin/user-edit.html")
	var output bytes.Buffer
	_ = template.Must(template.New("Edit User").Parse(string(rawTemplate))).Execute(&output, data)
	context.Body = base.NewPage("Edit User", context.NavigationBar, output.String())
	return false
}

func updatePassword(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	password := context.Request.PostFormValue(symbols.Password)
	succeed := mw.AdminUpdatePassword(context.Request, username, password)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func updateStatus(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	isAdmin := context.Request.PostFormValue(symbols.IsAdmin) == "on"
	isEnabled := context.Request.PostFormValue(symbols.IsEnabled) == "on"
	succeed := mw.AdminUpdateStatus(context.Request, username, isAdmin, isEnabled)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func deleteARPSpoofInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminDeleteARPSpoofInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func addARPSpoofInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminAddARPSpoofInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func deleteARPScanInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminDeleteARPScanInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func addARPScanInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminAddARPScanInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func deleteCaptureInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminDeleteCaptureInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
	return false
}

func addCaptureInterface(mw *middleware.Middleware, context *middleware.Context) bool {
	username := context.Request.PostFormValue(symbols.Username)
	i := context.Request.PostFormValue(symbols.Interface)
	succeed := mw.AdminAddCaptureInterfacePrivilege(context.Request, username, i)
	responseBody, _ := json.Marshal(succeedResponse{succeed})
	context.Headers["Content-Type"] = "application/json"
	context.Body = string(responseBody)
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
