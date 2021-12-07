package spoof

import (
	"bytes"
	"encoding/json"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
	"net"
)

type succeedResponse struct {
	Succeed bool
	Message string
}

func testArguments(mw *middleware.Middleware, context *middleware.Context, ip, gateway, arpInterface string) succeedResponse {
	var responseObject succeedResponse

	responseObject.Succeed = false

	succeed, _, _, _, arpSpoofInterfaces, getError := mw.GetUserInterfacePermissions(context.User.Username)
	if getError != nil {
		go mw.LogError(context.Request, getError)
		responseObject.Message = "Something goes wrong"
		return responseObject
	}

	func() {
		if !succeed {
			responseObject.Message = "Failed to query user interfaces"
			return
		}

		if net.ParseIP(ip) == nil {
			responseObject.Message = "Invalid IP provided"
			return
		}
		if net.ParseIP(gateway) == nil {
			responseObject.Message = "Invalid Gateway IP provided"
			return
		}

		if _, found := arpSpoofInterfaces[arpInterface]; !found {
			responseObject.Message = "No permissions for selected interface"
			return
		}
		connectedInterfaces := mw.ListNetInterfaces(context.Request)
		if connectedInterfaces == nil {
			responseObject.Message = "Failed to list connected interfaces"
			return
		}
		if _, found := connectedInterfaces[arpInterface]; !found {
			responseObject.Message = "User has permissions but the interface is not connected to the machine"
			return
		}
		responseObject.Message = "Everything ok!"
		responseObject.Succeed = true
	}()

	return responseObject
}

func testARPSpoofArguments(mw *middleware.Middleware, context *middleware.Context) bool {
	arpInterface := context.Request.PostFormValue(symbols.Interface)
	ip := context.Request.PostFormValue(symbols.IP)
	gateway := context.Request.PostFormValue(symbols.Gateway)

	responseObject := testArguments(mw, context, ip, gateway, arpInterface)

	response, marshalError := json.Marshal(responseObject)
	if marshalError != nil {
		go mw.LogError(context.Request, marshalError)
		context.Body = "{\"Succeed\": false, \"Message\": \"Something goes wrong\"}"
		return false
	}
	context.Body = string(response)
	return false
}

func handleARPSpoof(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Implement me
	return false
}

func ARPSpoof(mw *middleware.Middleware, context *middleware.Context) bool {
	action := context.Request.FormValue(actions.Action)
	switch action {
	case actions.Test:
		return testARPSpoofArguments(mw, context)
	case actions.Spoof:
		return handleARPSpoof(mw, context)
	}
	succeed, _, _, _, arpSpoofPermissions, getPermissionsError := mw.GetUserInterfacePermissions(context.User.Username)
	if getPermissionsError != nil {
		go mw.LogError(context.Request, getPermissionsError)
		context.Redirect = symbols.UserARP
		return false
	}
	if !succeed {
		context.Redirect = symbols.UserARP
		return false
	}
	connectedInterface := mw.ListNetInterfaces(context.Request)
	var targetInterfaces []struct {
		Name    string
		Address string
	}
	for _, permission := range arpSpoofPermissions {
		i, found := connectedInterface[permission.Interface]
		if found {
			for _, address := range i.Addresses {
				targetInterfaces = append(targetInterfaces,
					struct {
						Name    string
						Address string
					}{
						Name:    i.Name,
						Address: address.IP.String(),
					},
				)
			}
		}
	}
	rawMenu, _ := mw.Templates.ReadFile("templates/user/arp/spoof.html")
	var menu bytes.Buffer
	_ = template.Must(template.New("ARP spoof").Parse(string(rawMenu))).Execute(&menu,
		struct {
			ARPSpoofInterfaces []struct {
				Name    string
				Address string
			}
		}{
			ARPSpoofInterfaces: targetInterfaces,
		},
	)
	context.Body = base.NewPage("ARP Spoof", context.NavigationBar, menu.String())
	return false
}
