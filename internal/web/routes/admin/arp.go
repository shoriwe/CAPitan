package admin

import (
	"bytes"
	"encoding/json"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html"
	"html/template"
	"net/http"
)

func viewARPScan(mw *middleware.Middleware, context *middleware.Context) bool {
	scanName := context.Request.PostFormValue(symbols.ScanName)
	username := context.Request.PostFormValue(symbols.Username)
	succeed, scanSession := mw.UserGetARPScan(context.Request, username, scanName)
	if !succeed {
		context.Redirect = symbols.AdminARPScans
		return false
	}

	var hosts []struct {
		IP  string
		MAC string
	}
	unmarshalError := json.Unmarshal(scanSession.Hosts, &hosts)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
		context.Redirect = symbols.AdminARPScans
		return false
	}

	templateContents, _ := mw.Templates.ReadFile("templates/admin/arp-view.html")
	var body bytes.Buffer
	err := template.Must(template.New("ARP scan view").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Username      string
			ScanName      string
			InterfaceName string
			Script        string
			Hosts         []struct {
				IP  string
				MAC string
			}
		}{
			Username:      username,
			ScanName:      html.EscapeString(scanSession.Name),
			InterfaceName: html.EscapeString(scanSession.Interface),
			Script:        html.EscapeString(string(scanSession.Script)),
			Hosts:         hosts,
		},
	)
	if err != nil {
		context.Redirect = symbols.Dashboard
		go mw.LogError(context.Request, err)
	}
	context.Body = base.NewPage("View ARP scan", context.NavigationBar, body.String())
	return false
}

func downloadUserARPScan(mw *middleware.Middleware, context *middleware.Context) bool {
	scanName := context.Request.PostFormValue(symbols.ScanName)
	username := context.Request.PostFormValue(symbols.Username)
	succeed, scanSession := mw.UserGetARPScan(context.Request, username, scanName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	context.ResponseWriter.Header().Add("Content-Disposition", "attachment; filename=\"arp-scan.json\"")
	_, writeError := context.ResponseWriter.Write(scanSession.Hosts)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	context.WriteBody = false
	return false
}

func handleARPPost(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.View:
		return viewARPScan(mw, context)
	case actions.Download:
		return downloadUserARPScan(mw, context)
	}
	context.Redirect = symbols.AdminARPScans
	return false
}

func listUserARPScans(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, scans := mw.AdminListAllARPScans(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.AdminPanel
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/admin/arp-list.html")
	var body bytes.Buffer
	err := template.Must(template.New("ARP scan list").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Scans []*objects.ARPScanSessionAdminView
		}{
			Scans: scans,
		},
	)
	if err != nil {
		context.Redirect = symbols.Dashboard
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("ARP scans", context.NavigationBar, body.String())
	return false
}

func ListUserARPScans(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		return listUserARPScans(mw, context)
	case http.MethodPost:
		return handleARPPost(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}
