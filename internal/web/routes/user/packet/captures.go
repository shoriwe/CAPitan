package packet

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"regexp"
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
	fmt.Println(0)
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
	fmt.Println(1)
	readError := connection.ReadJSON(&configuration)
	if readError != nil {
		go mw.LogError(context.Request, readError)
		// TODO: Send this to client
		return false
	}
	fmt.Println(2)
	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, configuration.CaptureName) {
		context.Redirect = symbols.UserPacketCaptures
		return false
	}
	fmt.Println(3)
	engine := capture.NewEngine(configuration.InterfaceName)
	engine.Promiscuous = configuration.Promiscuous
	if len(configuration.Script) > 0 {
		initError := engine.InitScript(configuration.Script)
		if initError != nil {
			go mw.LogError(context.Request, initError)
			// TODO: Return this to the client
			return false
		}
	}
	packetChannel, tcpStreamChannel, startError := engine.Start()
	if startError != nil {
		go mw.LogError(context.Request, startError)
		// TODO: Return this to the client
		return false
	}
	defer engine.Close()

	fmt.Println(packetChannel, tcpStreamChannel, configuration.Description)

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
		var menu bytes.Buffer
		_ = template.Must(template.New("New Capture").Parse(string(menuTemplate))).Execute(&menu,
			struct {
				CaptureInterfaces map[string]struct{}
			}{
				CaptureInterfaces: captureInterfaces,
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
