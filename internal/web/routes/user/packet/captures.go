package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"github.com/shoriwe/gplasma/pkg/compiler/lexer"
	"github.com/shoriwe/gplasma/pkg/compiler/parser"
	"github.com/shoriwe/gplasma/pkg/reader"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"time"
)

var (
	stringChecker = regexp.MustCompile("\\w+[\\w\\s]*")
	upgrade       = websocket.Upgrader{
		ReadBufferSize:    0, /* 1 megabyte*/
		WriteBufferSize:   0, /* 1 megabyte*/
		EnableCompression: true,
		Subprotocols:      []string{"PacketCaptureSession"},
	}
)

type serverResponse struct {
	Type    string
	Payload interface{}
}

func listCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userCaptures := mw.ListUserCaptures(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.UserPacket
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/user/packet/captures/list.html")
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
		context.Redirect = symbols.UserPacket
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Packet", context.NavigationBar, body.String())
	return false
}

func checkCaptureInput(mw *middleware.Middleware, context *middleware.Context) (bool, string) {
	if context.Request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		// TODO: Better handling?
		return false, ""
	}

	interfaceName := context.Request.FormValue(symbols.Interface)
	captureName := context.Request.FormValue(symbols.CaptureName)
	description := context.Request.FormValue(symbols.Description)
	script := context.Request.FormValue(symbols.Script)

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

func testCaptureArguments(mw *middleware.Middleware, context *middleware.Context) bool {
	var response struct {
		Succeed bool
		Error   string
	}
	response.Succeed, response.Error = checkCaptureInput(mw, context)
	body, marshalError := json.Marshal(response)
	if marshalError != nil {
		go mw.LogError(context.Request, marshalError)
		return false
	}
	context.Body = string(body)
	return false
}

func prepareCaptureSession(mw *middleware.Middleware, context *middleware.Context) bool {
	connection, upgradeError := upgrade.Upgrade(context.ResponseWriter, context.Request, context.ResponseWriter.Header())
	if upgradeError != nil {
		go mw.LogError(context.Request, upgradeError)
		context.Redirect = symbols.UserPacketCaptures
		return false
	}
	context.WriteBody = false
	defer func() {
		closeError := connection.Close()
		go mw.LogError(context.Request, closeError)
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
	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, configuration.CaptureName) {
		return false
	}
	defer mw.RemoveReservedCaptureName(context.Request, context.User.Username, configuration.CaptureName)

	engine := capture.NewEngine(configuration.InterfaceName)
	defer engine.Close()
	engine.Promiscuous = configuration.Promiscuous

	if len(configuration.Script) > 0 {
		initError := engine.InitScript(configuration.Script)
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

	stopChannel := make(chan bool, 1)
	go func() {
		var action struct {
			Action string
		}
		err := connection.ReadJSON(&action)
		if err != nil {
			go mw.LogError(context.Request, err)
			engine.ErrorChannel <- err
			return
		}
		switch action.Action {
		case "STOP":
			stopChannel <- true
		}
	}()

	tick := time.Tick(time.Second)

	tempFile, tempFileCreationError := os.CreateTemp("", context.User.Username+configuration.CaptureName+".pcap")
	if tempFileCreationError != nil {
		go mw.LogError(context.Request, tempFileCreationError)
		return false
	}
	defer func() {
		closeError := tempFile.Close()
		if closeError != nil {
			go mw.LogError(context.Request, closeError)
		}
		removeError := os.Remove(tempFile.Name())
		if removeError != nil {
			go mw.LogError(context.Request, removeError)
		}
	}()

	hashedStreams := map[[16]byte]struct{}{}

	pcapFile := pcapgo.NewWriter(tempFile)

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
					writeError := connection.WriteJSON(serverResponse{
						Type:    "error",
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
							packetWriteError := pcapFile.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
							if packetWriteError != nil {
								go mw.LogError(context.Request, packetWriteError)
								return false
							}
							//Send the packet to the client
							writeError := connection.WriteJSON(
								serverResponse{
									Type:    "packet",
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

							// TODO: Do something to temporally store the packet
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
								serverResponse{
									Type:    "stream",
									Payload: data,
								},
							)
							if writeError != nil {
								go mw.LogError(context.Request, writeError)
								return false
							}
						}
						// TODO: Do something to temporally store the stream
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
					serverResponse{
						Type: "update-graphs",
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  "topology",
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
					serverResponse{
						Type: "update-graphs",
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  "host-packet-count",
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
					serverResponse{
						Type: "update-graphs",
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  "layer-4-graph",
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
					serverResponse{
						Type: "update-graphs",
						Payload: struct {
							Target  string
							Options interface{}
						}{
							Target:  "stream-type-graph",
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
	closeError := tempFile.Close()
	if closeError != nil {
		go mw.LogError(context.Request, closeError)
		return false
	}

	// TODO: if the capture reached to here means that it is valid to be stored in the database
	return false
}

func newCapture(mw *middleware.Middleware, context *middleware.Context) bool {
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
		menuTemplate, _ := mw.Templates.ReadFile("templates/user/packet/captures/new-menu.html")

		var availableInterfaces []objects.InterfaceInformation
		{
		}
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

func Captures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue("action") {
	case actions.NewCapture:
		return newCapture(mw, context)
	case actions.ImportCapture:
		break
	case actions.TestCaptureArguments:
		return testCaptureArguments(mw, context)
	case actions.Start:
		return prepareCaptureSession(mw, context)
	}
	return listCaptures(mw, context)
}
