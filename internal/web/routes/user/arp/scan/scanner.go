package scan

import (
	"bytes"
	"github.com/gorilla/websocket"
	arp_scanner "github.com/shoriwe/CAPitan/internal/arp-scanner"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"html/template"
	"regexp"
	"time"
)

var (
	whiteSpace            = regexp.MustCompile("(?m)^\\s+$")
	upgradeARPScanSession = websocket.Upgrader{
		ReadBufferSize:    0, /* No Limit */
		WriteBufferSize:   0, /* No Limit */
		EnableCompression: true,
		Subprotocols:      []string{"ARPScanSession"},
	}
)

func checkScanArguments(scanName, script string) (bool, string) {
	if len(scanName) == 0 {
		return false, "no scan name provided"
	}
	if len(script) == 0 {
		return false, "no host generator script provided"
	}
	if whiteSpace.MatchString(scanName) {
		return false, "no scan name provided"
	}
	if whiteSpace.MatchString(script) {
		return false, "no host generator script provided"
	}
	return true, ""
}

func handleNewScan(mw *middleware.Middleware, context *middleware.Context) bool {
	connection, upgradeError := upgradeARPScanSession.Upgrade(context.ResponseWriter, context.Request, context.ResponseWriter.Header())
	if upgradeError != nil {
		go mw.LogError(context.Request, upgradeError)
		context.Redirect = symbols.UserARPSpoof
		return false
	}
	context.WriteBody = false
	defer func() {
		closeError := connection.Close()
		if closeError != nil {
			go mw.LogError(context.Request, closeError)
		}
	}()

	var configuration struct {
		ScanName      string
		InterfaceName string
		Script        string
	}
	readError := connection.ReadJSON(&configuration)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		return false
	}
	// Check configuration
	isValid, errorMessage := checkScanArguments(configuration.ScanName, configuration.Script)
	if !isValid {
		writeError := connection.WriteJSON(struct {
			Succeed bool
			Message string
		}{
			Succeed: false,
			Message: errorMessage,
		})
		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
		return false
	}
	// Respond to the client if everything is ok
	if !mw.ReserveUserARPScanName(context.Request, context.User.Username, configuration.ScanName) {
		writeError := connection.WriteJSON(
			struct {
				Succeed bool
				Message string
			}{
				Succeed: false,
				Message: "Scan name already taken",
			},
		)

		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
		return false
	}
	defer mw.RemoveReservedARPScanName(context.Request, context.User.Username, configuration.ScanName)

	engine, engineCreationError := arp_scanner.NewEngine(configuration.InterfaceName, configuration.Script)
	if engineCreationError != nil {
		go mw.LogError(context.Request, engineCreationError)
		writeError := connection.WriteJSON(
			struct {
				Succeed bool
				Message string
			}{
				Succeed: false,
				Message: engineCreationError.Error(),
			},
		)

		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
		return false
	}
	defer engine.Close()

	writeError := connection.WriteJSON(struct {
		Succeed bool
		Message string
	}{
		Succeed: true,
		Message: "Everything ok!",
	},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}

	stopChannel := make(chan bool, 1)
	go func() {
		var action struct {
			Action string
		}
		err := connection.ReadJSON(&action)
		if err != nil {
			go mw.LogError(context.Request, err)
			engine.ErrorChannel <- err
			stopChannel <- true
			return
		}
		switch action.Action {
		case symbols.StopSignal:
			stopChannel <- true
		}
	}()

	tick := time.Tick(500 * time.Millisecond)

	hostsSet := map[string]struct{}{}

	var hosts []struct {
		IP  string
		MAC string
	}

	engine.Start()

	start := time.Now()
mainLoop:
	for {
		select {
		case <-stopChannel:
			break mainLoop
		case engineError, isOpen := <-engine.ErrorChannel:
			if isOpen {
				go mw.LogError(context.Request, engineError)
				writeError = connection.WriteJSON(
					tools.ServerWSResponse{
						Type:    symbols.ErrorResponse,
						Payload: engineError.Error(),
					},
				)
				if writeError != nil {
					mw.LogError(context.Request, writeError)
				}
				return false
			} else {
				break mainLoop
			}
		case <-tick:
		scanLoop:
			for i := 0; i < 1000; i++ {
				select {
				case host, isOpen := <-engine.Hosts:
					if isOpen {
						if _, found := hostsSet[host.IP.To4().String()]; !found {
							hostsSet[host.IP.To4().String()] = struct{}{}
							hosts = append(
								hosts,
								struct {
									IP  string
									MAC string
								}{
									IP:  host.IP.To4().String(),
									MAC: host.MAC.String(),
								},
							)
							writeError = connection.WriteJSON(tools.ServerWSResponse{
								Type: symbols.HostResponse,
								Payload: struct {
									IP  string
									MAC string
								}{
									IP:  host.IP.To4().String(),
									MAC: host.MAC.String(),
								},
							})
							if writeError != nil {
								go mw.LogError(context.Request, writeError)
								return false
							}
						}
					} else {
						break mainLoop
					}
				default:
					break scanLoop
				}
			}
		}
	}

	finish := time.Now()

	// Send to the client that it is safe to close the connection

	writeError = connection.WriteJSON(
		struct {
			Succeed bool
		}{
			Succeed: true,
		},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}

	mw.SaveARPScan(
		context.Request,
		context.User.Username,
		configuration.ScanName,
		configuration.InterfaceName,
		configuration.Script,
		hosts,
		start, finish,
	)
	return false
}

func renderController(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, _, _, arpScanPermissions, _, getPermissionsError := mw.GetUserInterfacePermissions(context.User.Username)
	if getPermissionsError != nil {
		go mw.LogError(context.Request, getPermissionsError)
		context.Redirect = symbols.UserARP
		return false
	}

	if !succeed {
		return false
	}

	connectedInterface := mw.ListNetInterfaces(context.Request)
	var targetInterfaces []struct {
		Name    string
		Address string
	}
	for _, permission := range arpScanPermissions {
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

	renderTemplate, _ := mw.Templates.ReadFile("templates/user/arp/scan.html")
	var output bytes.Buffer
	templateExecutionError := template.Must(template.New("Scan").Parse(string(renderTemplate))).Execute(
		&output,
		struct {
			ARPScanInterfaces []struct {
				Name    string
				Address string
			}
		}{
			ARPScanInterfaces: targetInterfaces,
		},
	)
	if templateExecutionError != nil {
		go mw.LogError(context.Request, templateExecutionError)
		return false
	}
	context.Body = base.NewPage("View Packet", context.NavigationBar, output.String())
	return false
}

func viewScan(mw *middleware.Middleware, context *middleware.Context) bool {
	// TODO: Implement me
	return false
}

func listScans(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userARPScans := mw.ListUserARPScans(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/user/arp/scan-list.html")
	var body bytes.Buffer
	err := template.Must(template.New("Packet").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Scans []*objects.ARPScanSession
		}{
			Scans: userARPScans,
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

func downloadScan(mw *middleware.Middleware, context *middleware.Context) bool {
	scanName := context.Request.PostFormValue(symbols.ScanName)
	succeed, scanSession := mw.UserGetARPScan(context.Request, context.User.Username, scanName)
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

func ARPScan(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.New:
		return handleNewScan(mw, context)
	case actions.View:
		return viewScan(mw, context)
	case actions.List:
		return listScans(mw, context)
	case actions.Download:
		return downloadScan(mw, context)
	}
	return renderController(mw, context)
}
