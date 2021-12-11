package packet

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"html"
	"html/template"
	"net/http"
)

var upgradeViewSession = websocket.Upgrader{
	ReadBufferSize:    0, /* No Limit */
	WriteBufferSize:   0, /* No Limit */
	EnableCompression: true,
	Subprotocols:      []string{"PacketViewSession"},
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
