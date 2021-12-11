package admin

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
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
	username := context.Request.PostFormValue(symbols.Username)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, username, captureName)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	var output bytes.Buffer
	renderTemplate, _ := mw.Templates.ReadFile("templates/admin/capture-view.html")
	executeError := template.Must(template.New("Render").Parse(string(renderTemplate))).Execute(
		&output,
		struct {
			RawUsername    string
			RawCaptureName string
			CaptureName    string
			Description    string
			Script         string
		}{
			RawUsername:    username,
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
	context.Body = base.NewPage("Admin View Packet", context.NavigationBar, output.String())
	return false
}

func viewCaptureWS(mw *middleware.Middleware, context *middleware.Context) bool {
	connection, upgradeError := upgradeViewSession.Upgrade(context.ResponseWriter, context.Request, context.ResponseWriter.Header())
	if upgradeError != nil {
		go mw.LogError(context.Request, upgradeError)
		context.Redirect = symbols.AdminPacketCaptures
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
		Username    string
		CaptureName string
	}
	readError := connection.ReadJSON(&request)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		return false
	}

	// Prepare the data to send

	succeed, captureSession, packets, streams := mw.UserGetCapture(context.Request, request.Username, request.CaptureName)
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

func handleCaptureView(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.Method {
	case http.MethodGet:
		return viewCaptureWS(mw, context)
	case http.MethodPost:
		return renderOldCapture(mw, context)
	}
	return http405.MethodNotAllowed(mw, context)
}

func downloadCapture(mw *middleware.Middleware, context *middleware.Context) bool {
	captureName := context.Request.PostFormValue(symbols.CaptureName)
	username := context.Request.PostFormValue(symbols.Username)
	succeed, captureSession, _, _ := mw.UserGetCapture(context.Request, username, captureName)
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

func listCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	succeed, userCaptures := mw.AdminListAllCaptures(context.Request, context.User.Username)
	if !succeed {
		context.Redirect = symbols.Dashboard
		return false
	}
	templateContents, _ := mw.Templates.ReadFile("templates/admin/capture-list.html")
	var body bytes.Buffer
	err := template.Must(template.New("Admin Packet").Parse(string(templateContents))).Execute(
		&body,
		struct {
			Captures []*objects.CaptureSessionAdminView
		}{
			Captures: userCaptures,
		},
	)
	if err != nil {
		context.Redirect = symbols.Dashboard
		go mw.LogError(context.Request, err)
		return false
	}
	context.Body = base.NewPage("Admin Packet", context.NavigationBar, body.String())
	return false
}

func PacketCaptures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.View:
		return handleCaptureView(mw, context)
	case actions.Download:
		return downloadCapture(mw, context)
	}
	return listCaptures(mw, context)
}
