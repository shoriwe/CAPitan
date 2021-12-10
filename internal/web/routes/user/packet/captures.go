package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"github.com/shoriwe/gplasma/pkg/compiler/lexer"
	"github.com/shoriwe/gplasma/pkg/compiler/parser"
	"github.com/shoriwe/gplasma/pkg/reader"
	"html"
	"html/template"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

var (
	stringChecker         = regexp.MustCompile("\\w+[\\w\\s]*")
	upgradeCaptureSession = websocket.Upgrader{
		ReadBufferSize:    0, /* No Limit */
		WriteBufferSize:   0, /* No Limit */
		EnableCompression: true,
		Subprotocols:      []string{"PacketCaptureSession"},
	}
	upgradeViewSession = websocket.Upgrader{
		ReadBufferSize:    0, /* No Limit */
		WriteBufferSize:   0, /* No Limit */
		EnableCompression: true,
		Subprotocols:      []string{"PacketViewSession"},
	}
)

func listCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userCaptures := mw.ListUserCaptures(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/user/packet/list.html")
	var body bytes.Buffer
	err := template.Must(template.New("Packet").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Username string
			Captures []*objects.CaptureSession
		}{
			Username: context.User.Username,
			Captures: userCaptures,
		},
	)
	if err != nil {
		context.Redirect = symbols.Dashboard
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Packet", context.NavigationBar, body.String())
	return false
}

func checkInterfaceCaptureInputArguments(mw *middleware.Middleware, context *middleware.Context, captureName, interfaceName, description, script string) (bool, string) {
	if len(script) > 0 {
		// Test that the script successfully compiles to plasma bytecode
		finalProgram, parsingError := parser.NewParser(lexer.NewLexer(reader.NewStringReader(script))).Parse()
		if parsingError != nil {
			go mw.LogError(context.Request, parsingError.Error())
			return false, parsingError.String()
		}
		_, compileError := finalProgram.Compile()
		if compileError != nil {
			go mw.LogError(context.Request, compileError.Error())
			return false, compileError.String()
		}
	}
	// Check the interface name is a valid string
	if !stringChecker.MatchString(interfaceName) {
		return false, "Please, select only the interfaces you have permission to use, if this is a CVE, report it to the github repo, I will try to fixit and give you a month of VIP in HTB"
	}
	// Check the interface is associated with the user
	succeed, _, captureInterfaces, _, _, getError := mw.GetUserInterfacePermissions(context.User.Username)
	if getError != nil {
		go mw.LogError(context.Request, getError)
		return false, "Something goes wrong"
	}
	if !succeed {
		return false, "Could not confirm user capture interfaces"
	}
	if _, found := captureInterfaces[interfaceName]; !found {
		return false, "User do not have permission for the selected interface"
	}
	// Check the capture is a valid string
	if !stringChecker.MatchString(captureName) {
		return false, "Capture name does not accomplish \\w+[\\w\\s]*"
	}
	// Check the capture is unique for the user
	if mw.UserCaptureNameAlreadyTaken(context.Request, context.User.Username, captureName) {
		return false, "Capture name is already in use"
	}
	// Check the description is a valid string
	if !stringChecker.MatchString(description) {
		return false, "Description does not accomplish \\w+[\\w\\s]*"
	}
	return true, "succeed"
}

func testInterfaceBasedCaptureArguments(mw *middleware.Middleware, context *middleware.Context) bool {
	var response struct {
		Succeed bool
		Error   string
	}

	interfaceName := context.Request.PostFormValue(symbols.Interface)
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	description := context.Request.PostFormValue(symbols.Description)
	script := context.Request.PostFormValue(symbols.Script)

	response.Succeed, response.Error = checkInterfaceCaptureInputArguments(mw, context, captureName, interfaceName, description, script)
	body, marshalError := json.Marshal(response)
	if marshalError != nil {
		go mw.LogError(context.Request, marshalError)
		return false
	}
	context.Body = string(body)
	return false
}

func startInterfaceBasedCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	connection, upgradeError := upgradeCaptureSession.Upgrade(context.ResponseWriter, context.Request, context.ResponseWriter.Header())
	if upgradeError != nil {
		go mw.LogError(context.Request, upgradeError)
		context.Redirect = symbols.UserPacketCaptures
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
		Promiscuous   bool
		Script        string
		Description   string
		CaptureName   string
		InterfaceName string
	}
	readError := connection.ReadJSON(&configuration)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		return false
	}
	// Check configuration
	isValid, errorMessage := checkInterfaceCaptureInputArguments(mw, context, configuration.CaptureName, configuration.InterfaceName, configuration.Description, configuration.Script)
	if isValid {
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

	} else {
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
	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, configuration.CaptureName) {
		return false
	}
	defer mw.RemoveReservedCaptureName(context.Request, context.User.Username, configuration.CaptureName)

	engine := capture.NewEngineWithInterface(configuration.InterfaceName)
	defer engine.Close()
	engine.Promiscuous = configuration.Promiscuous

	if len(configuration.Script) > 0 {
		initError := engine.InitScript(configuration.Script)
		if initError != nil {
			go mw.LogError(context.Request, initError)
			return false
		}
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

	tick := time.Tick(time.Second)

	// Temporary storage of streams and packets
	var (
		packets []gopacket.Packet
		streams []capture.Data
	)

	hashedStreams := map[[16]byte]struct{}{}

	startError := engine.Start()
	if startError != nil {
		go mw.LogError(context.Request, startError)
		return false
	}

	// Graphs data
	var (
		topology        = objects.NewTopology()
		hostPacketCount = objects.NewCounter()
		layer4Count     = objects.NewCounter()
		streamTypeCount = objects.NewCounter()
	)

	start := time.Now()
masterLoop:
	for {
		select {
		case err, isOpen := <-engine.ErrorChannel:
			if isOpen {
				if err != nil {
					writeError := connection.WriteJSON(tools.ServerWSResponse{
						Type:    symbols.ErrorResponse,
						Payload: err.Error(),
					})
					if writeError != nil {
						go mw.LogError(context.Request, writeError)
					}
					return false
				}
			} else {
				break masterLoop
			}
		case stop, isOpen := <-stopChannel:
			if isOpen {
				if stop {
					break masterLoop
				}
			}
		case <-tick:
			updatedTopology := false
			updatedPacketCountPerHost := false
			updatedLayer4Count := false
			updatedStreamTypeCount := false
			for i := 0; i < 1000; i++ {
				select {
				case packet, isOpen := <-engine.Packets:
					if isOpen {
						if packet != nil {
							//Send the packet to the client
							writeError := connection.WriteJSON(
								tools.ServerWSResponse{
									Type:    symbols.PacketResponse,
									Payload: capture.TransformPacketToMap(packet),
								},
							)
							if writeError != nil {
								go mw.LogError(context.Request, writeError)
								return false
							}

							// Send the topology graph update
							updatedPacketCountPerHost = true
							updatedLayer4Count = true

							if topology.AddEdge(packet.NetworkLayer().NetworkFlow().Src().String(), packet.NetworkLayer().NetworkFlow().Dst().String()) && !updatedTopology {
								updatedTopology = true
							}
							hostPacketCount.Count(packet.NetworkLayer().NetworkFlow().Src().String())
							layer4Count.Count(packet.TransportLayer().LayerType().String())

							packets = append(packets, packet)
						}
					} else {
						break masterLoop
					}
					break
				case data, isOpen := <-engine.TCPStreams:
					if isOpen {
						updatedStreamTypeCount = true
						streamTypeCount.Count(data.Type)

						if _, found := hashedStreams[md5.Sum(data.Content)]; !found {
							writeError := connection.WriteJSON(
								tools.ServerWSResponse{
									Type:    symbols.StreamResponse,
									Payload: data,
								},
							)
							if writeError != nil {
								go mw.LogError(context.Request, writeError)
								return false
							}
						}

						streams = append(streams, data)
					} else {
						break masterLoop
					}
				default:
					break
				}
			}
			if updatedTopology {
				// Update graphs
				writeError := connection.WriteJSON(
					tools.ServerWSResponse{
						Type: symbols.UpdateGraphsResponse,
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  symbols.UpdateTopologyGraph,
							Options: topology.Options(),
						},
					},
				)
				if writeError != nil {
					go mw.LogError(context.Request, writeError)
					return false
				}
			}
			if updatedPacketCountPerHost {
				writeError := connection.WriteJSON(
					tools.ServerWSResponse{
						Type: symbols.UpdateGraphsResponse,
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  symbols.UpdateHostCountGraph,
							Options: hostPacketCount.Options(),
						},
					},
				)
				if writeError != nil {
					go mw.LogError(context.Request, writeError)
					return false
				}
			}
			if updatedLayer4Count {
				writeError := connection.WriteJSON(
					tools.ServerWSResponse{
						Type: symbols.UpdateGraphsResponse,
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  symbols.UpdateLayer4Graph,
							Options: layer4Count.Options(),
						},
					},
				)
				if writeError != nil {
					go mw.LogError(context.Request, writeError)
					return false
				}
			}
			if updatedStreamTypeCount {
				writeError := connection.WriteJSON(
					tools.ServerWSResponse{
						Type: symbols.UpdateGraphsResponse,
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  symbols.UpdateStreamCountGraph,
							Options: streamTypeCount.Options(),
						},
					},
				)
				if writeError != nil {
					go mw.LogError(context.Request, writeError)
					return false
				}
			}
		}
	}

	finish := time.Now()

	// Send to the client that it is safe to close the connection

	writeError := connection.WriteJSON(struct {
		Succeed bool
	}{
		Succeed: true,
	})
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}

	mw.SaveInterfaceCapture(
		context.Request,
		context.User.Username,
		configuration.CaptureName,
		configuration.InterfaceName,
		configuration.Description,
		configuration.Script,
		configuration.Promiscuous,
		topology.Options(),
		hostPacketCount.Options(),
		layer4Count.Options(),
		streamTypeCount.Options(),
		packets,
		streams,
		engine.DumpPcap(),
		start, finish,
	)
	return false
}

func newInterfaceCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		succeed, _, captureInterfaces, _, _, getError := mw.GetUserInterfacePermissions(context.User.Username)
		if getError != nil {
			go mw.LogError(context.Request, getError)
			return false
		}
		if !succeed {
			// TODO: Log this
			return false
		}
		menuTemplate, _ := mw.Templates.ReadFile("templates/user/packet/new-interface-capture.html")

		var availableInterfaces []objects.InterfaceInformation
		connectedInterfaces := mw.ListNetInterfaces(context.Request)
		for interfaceName, networkInterface := range connectedInterfaces {
			if _, found := captureInterfaces[interfaceName]; found {
				var iAddress string
				for _, address := range networkInterface.Addresses {
					iAddress = address.IP.String()
				}
				information := objects.InterfaceInformation{
					Name:    interfaceName,
					Address: iAddress,
				}
				availableInterfaces = append(availableInterfaces, information)
			}
		}
		var menu bytes.Buffer
		_ = template.Must(template.New("New Capture").Parse(string(menuTemplate))).Execute(&menu,
			struct {
				CaptureInterfaces []objects.InterfaceInformation
			}{
				CaptureInterfaces: availableInterfaces,
			},
		)
		context.Body = base.NewPage("Packet", context.NavigationBar, menu.String())
		return false
	}
	return http405.MethodNotAllowed(mw, context)
}

func importCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		templateContents, _ := mw.Templates.ReadFile("templates/user/packet/import-capture.html")
		context.Body = base.NewPage("Import", context.NavigationBar, string(templateContents))
		return false
	case http.MethodPost:
		return handleImportCapture(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}

func handleImportCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	parseError := context.Request.ParseMultipartForm(1024 * 1024 * 1024 * 500)
	context.Redirect = symbols.UserPacketCaptures + "?action=" + actions.Import
	if parseError != nil {
		go mw.LogError(context.Request, parseError)

		return false
	}
	mimeFile, _, openError := context.Request.FormFile(symbols.File)
	if openError != nil {
		go mw.LogError(context.Request, openError)

		return false
	}
	file, tempCreationError := os.CreateTemp("", "*.pcap")
	if tempCreationError != nil {
		go mw.LogError(context.Request, tempCreationError)
		return false
	}
	_, copyError := io.Copy(file, mimeFile)
	if copyError != nil {
		go mw.LogError(context.Request, copyError)
		return false
	}
	closeError := file.Close()
	if closeError != nil {
		go mw.LogError(context.Request, closeError)
		return false
	}
	file, openError = os.Open(file.Name())
	if openError != nil {
		go mw.LogError(context.Request, openError)
		return false
	}
	defer file.Close()

	captureName := context.Request.PostFormValue(symbols.CaptureName)
	description := context.Request.PostFormValue(symbols.Description)
	script := context.Request.PostFormValue(symbols.Script)
	if len(script) > 0 {
		// Test that the script successfully compiles to plasma bytecode
		finalProgram, parsingError := parser.NewParser(lexer.NewLexer(reader.NewStringReader(script))).Parse()
		if parsingError != nil {
			go mw.LogError(context.Request, parsingError.Error())

			return false
		}
		_, compileError := finalProgram.Compile()
		if compileError != nil {
			go mw.LogError(context.Request, compileError.Error())

			return false
		}
	}
	// Check the capture is a valid string
	if !stringChecker.MatchString(captureName) {

		return false
	}
	// Check the capture is unique for the user
	if mw.UserCaptureNameAlreadyTaken(context.Request, context.User.Username, captureName) {

		return false
	}
	// Check the description is a valid string
	if !stringChecker.MatchString(description) {

		return false
	}

	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, captureName) {
		return false
	}
	defer mw.RemoveReservedCaptureName(context.Request, context.User.Username, captureName)

	engine := capture.NewEngineWithFile(file)
	defer engine.Close()

	if len(script) > 0 {
		initError := engine.InitScript(script)
		if initError != nil {
			go mw.LogError(context.Request, initError)
			return false
		}
	}
	startError := engine.Start()
	if startError != nil {
		go mw.LogError(context.Request, startError)
		return false
	}

	tick := time.Tick(time.Second)

	// Temporary storage of streams and packets
	var (
		packets []gopacket.Packet
		streams []capture.Data
	)

	hashedStreams := map[[16]byte]struct{}{}

	// Graphs data
	var (
		topology        = objects.NewTopology()
		hostPacketCount = objects.NewCounter()
		layer4Count     = objects.NewCounter()
		streamTypeCount = objects.NewCounter()
	)

masterLoop:
	for {
		select {
		case err, isOpen := <-engine.ErrorChannel:
			if isOpen {
				if err != nil {
					go mw.LogError(context.Request, err)

					return false
				}
			} else {
				break masterLoop
			}
		case <-tick:
			for i := 0; i < 1000; i++ {
				select {
				case packet, isOpen := <-engine.Packets:
					if isOpen {
						if packet != nil {
							topology.AddEdge(packet.NetworkLayer().NetworkFlow().Src().String(), packet.NetworkLayer().NetworkFlow().Dst().String())
							hostPacketCount.Count(packet.NetworkLayer().NetworkFlow().Src().String())
							layer4Count.Count(packet.TransportLayer().LayerType().String())
							packets = append(packets, packet)
						}
					} else {
						break masterLoop
					}
					break
				case data, isOpen := <-engine.TCPStreams:
					if isOpen {
						streamTypeCount.Count(data.Type)
						if _, found := hashedStreams[md5.Sum(data.Content)]; !found {
							streams = append(streams, data)
						}
					} else {
						break masterLoop
					}
				default:
					break masterLoop
				}
			}
		}
	}
	context.Redirect = symbols.UserPacketCaptures
	mw.SaveImportCapture(
		context.Request,
		context.User.Username,
		captureName,
		description,
		script,
		topology.Options(),
		hostPacketCount.Options(),
		layer4Count.Options(),
		streamTypeCount.Options(),
		packets,
		streams,
		engine.DumpPcap(),
	)
	return false
}

func renderOldCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, context.User.Username, captureName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	var output bytes.Buffer
	renderTemplate, _ := mw.Templates.ReadFile("templates/user/packet/view-capture.html")
	executeError := template.Must(template.New("Render").Parse(string(renderTemplate))).Execute(
		&output,
		struct {
			RawCaptureName string
			CaptureName    string
			Description    string
			Script         string
		}{
			RawCaptureName: captureName,
			CaptureName:    html.EscapeString(captureName),
			Description:    html.EscapeString(captureSession.Description),
			Script:         html.EscapeString(string(captureSession.FilterScript)),
		},
	)
	if executeError != nil {
		go mw.LogError(context.Request, executeError)
		return false
	}
	context.Body = base.NewPage("View Packet", context.NavigationBar, output.String())
	return false
}

func viewCaptureWS(mw *middleware.Middleware, context *middleware.Context) bool {
	connection, upgradeError := upgradeViewSession.Upgrade(context.ResponseWriter, context.Request, context.ResponseWriter.Header())
	if upgradeError != nil {
		go mw.LogError(context.Request, upgradeError)
		context.Redirect = symbols.UserPacketCaptures
		return false
	}
	context.WriteBody = false
	defer func() {
		closeError := connection.Close()
		if closeError != nil {
			go mw.LogError(context.Request, closeError)
		}
	}()

	var request struct {
		CaptureName string
	}
	readError := connection.ReadJSON(&request)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		return false
	}

	// Prepare the data to send

	succeed, captureSession, packets, streams := mw.UserGetCapture(context.Request, context.User.Username, request.CaptureName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}

	var topologyConfig interface{}
	unmarshalError := json.Unmarshal(captureSession.TopologyJson, &topologyConfig)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
		return false
	}
	var hostCountConfig interface{}
	unmarshalError = json.Unmarshal(captureSession.HostCountJson, &hostCountConfig)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
		return false
	}
	var streamCountConfig interface{}
	unmarshalError = json.Unmarshal(captureSession.StreamTypeCountJson, &streamCountConfig)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
		return false
	}
	var layerCountConfig interface{}
	unmarshalError = json.Unmarshal(captureSession.LayerCountJson, &layerCountConfig)
	if unmarshalError != nil {
		go mw.LogError(context.Request, unmarshalError)
		return false
	}

	// Send the graph configs

	writeError := connection.WriteJSON(
		tools.ServerWSResponse{
			Type: symbols.UpdateGraphsResponse,
			Payload: struct {
				Target  string
				Options interface{}
			}{
				Target:  symbols.UpdateLayer4Graph,
				Options: layerCountConfig,
			},
		},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	writeError = connection.WriteJSON(
		tools.ServerWSResponse{
			Type: symbols.UpdateGraphsResponse,
			Payload: struct {
				Target  string
				Options interface{}
			}{
				Target:  symbols.UpdateHostCountGraph,
				Options: hostCountConfig,
			},
		},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	writeError = connection.WriteJSON(
		tools.ServerWSResponse{
			Type: symbols.UpdateGraphsResponse,
			Payload: struct {
				Target  string
				Options interface{}
			}{
				Target:  symbols.UpdateTopologyGraph,
				Options: topologyConfig,
			},
		},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	writeError = connection.WriteJSON(
		tools.ServerWSResponse{
			Type: symbols.UpdateGraphsResponse,
			Payload: struct {
				Target  string
				Options interface{}
			}{
				Target:  symbols.UpdateStreamCountGraph,
				Options: streamCountConfig,
			},
		},
	)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}

	// Send the packets

	for _, packet := range packets {
		writeError = connection.WriteJSON(tools.ServerWSResponse{
			Type:    symbols.PacketResponse,
			Payload: packet,
		})
		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
	}

	// Send the streams

	for _, stream := range streams {
		writeError = connection.WriteJSON(tools.ServerWSResponse{
			Type:    symbols.StreamResponse,
			Payload: stream,
		})
		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
	}

	// Send to the client that it is safe to close the connection

	writeError = connection.WriteJSON(tools.ServerWSResponse{
		Type: symbols.StopSignal,
	})
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}

	return false
}

func viewCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodPost:
		return renderOldCapture(mw, context)
	case http.MethodGet:
		return viewCaptureWS(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}

func downloadCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, context.User.Username, captureName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	context.ResponseWriter.Header().Add("Content-Disposition", "attachment; filename=\"capture.pcap\"")
	_, writeError := context.ResponseWriter.Write(captureSession.Pcap)
	if writeError != nil {
		go mw.LogError(context.Request, writeError)
		return false
	}
	context.WriteBody = false
	return false
}

func Captures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.New:
		return newInterfaceCapture(mw, context)
	case actions.Import:
		return importCapture(mw, context)
	case actions.Test:
		return testInterfaceBasedCaptureArguments(mw, context)
	case actions.Start:
		return startInterfaceBasedCapture(mw, context)
	case actions.View:
		return viewCapture(mw, context)
	case actions.Download:
		return downloadCapture(mw, context)
	}
	return listCaptures(mw, context)
}
