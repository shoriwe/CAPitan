package spoof

import (
	"bytes"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
)

func ARPSpoof(mw *middleware.Middleware, context *middleware.Context) bool {
	action := context.Request.FormValue(actions.Action)
	switch action {
	case actions.Spoof:
		break
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
