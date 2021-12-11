package packet

import (
	"bytes"
	"crypto/md5"
	"github.com/google/gopacket"
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html/template"
	"net/http"
	"time"
)

var upgradeCaptureSession = websocket.Upgrader{
	ReadBufferSize:    0, /* No Limit */
	WriteBufferSize:   0, /* No Limit */
	EnableCompression: true,
	Subprotocols:      []string{"PacketCaptureSession"},
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
	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, configuration.CaptureName) {
		writeError := connection.WriteJSON(
			struct {
				Succeed bool
				Message string
			}{
				Succeed: false,
				Message: "Capture name already taken",
			},
		)

		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
		return false
	}
	defer mw.RemoveReservedCaptureName(context.Request, context.User.Username, configuration.CaptureName)

	engine, creationError := capture.NewEngineWithInterface(configuration.InterfaceName)
	if creationError != nil {
		go mw.LogError(context.Request, creationError)
		writeError := connection.WriteJSON(struct {
			Succeed bool
			Message string
		}{
			Succeed: false,
			Message: creationError.Error(),
		},
		)
		if writeError != nil {
			go mw.LogError(context.Request, writeError)
			return false
		}
		return false
	}
	// Respond to the client if everything is ok
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
					writeError = connection.WriteJSON(tools.ServerWSResponse{
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
							writeError = connection.WriteJSON(
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
							writeError = connection.WriteJSON(
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
				writeError = connection.WriteJSON(
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
				writeError = connection.WriteJSON(
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
				writeError = connection.WriteJSON(
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
				writeError = connection.WriteJSON(
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

	writeError = connection.WriteJSON(struct {
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
