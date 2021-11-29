package packet

import (
	"bytes"
	"encoding/json"
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

func Captures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue("action") {
	case actions.NewCapture:
		return newCapture(mw, context)
	case actions.ImportCapture:
		break
	case actions.TestCaptureArguments:
		return testCaptureArguments(mw, context)
	}
	return listCaptures(mw, context)
}

func testCaptureArguments(mw *middleware.Middleware, context *middleware.Context) bool {
	if context.Request.Method != http.MethodPost {
		return http405.MethodNotAllowed(mw, context)
	}
	if context.Request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		// TODO: Better handling?
		return false
	}
	var response struct {
		Succeed bool
		Error   string
	}
	interfaceName := context.Request.FormValue(symbols.Interface)
	captureName := context.Request.FormValue(symbols.CaptureName)
	description := context.Request.FormValue(symbols.Description)
	script := context.Request.FormValue(symbols.Script)
	// Test that the script successfully compiles to plasma bytecode
	finalProgram, parsingError := parser.NewParser(lexer.NewLexer(reader.NewStringReader(script))).Parse()
	if parsingError != nil {
		go mw.LogError(context.Request, parsingError.Error())
		response.Succeed = false
		response.Error = parsingError.String()
		result, _ := json.Marshal(response)
		context.Body = string(result)
		return false
	}
	_, compileError := finalProgram.Compile()
	if compileError != nil {
		go mw.LogError(context.Request, compileError.Error())
		response.Succeed = false
		response.Error = compileError.String()
		result, _ := json.Marshal(response)
		context.Body = string(result)
		return false
	}
	if !stringChecker.MatchString(interfaceName) {
		response.Succeed = false
		response.Error = "Please, select only the interfaces you have permission to use, if this is a CVE, report it to the github repo, I will try to fixit and give you a month of VIP in HTB"
		result, _ := json.Marshal(response)
		context.Body = string(result)
		return false
	}
	// TODO: Check if interface exists and is related to the user
	if !stringChecker.MatchString(captureName) {
		response.Succeed = false
		response.Error = "Capture name does not accomplish \\w+[\\w\\s]*"
		result, _ := json.Marshal(response)
		context.Body = string(result)
		return false
	}
	// TODO: Check if the name was already taken by the same user
	if !stringChecker.MatchString(description) {
		response.Succeed = false
		response.Error = "Description does not accomplish \\w+[\\w\\s]*"
		result, _ := json.Marshal(response)
		context.Body = string(result)
		return false
	}
	response.Succeed = true
	result, _ := json.Marshal(response)
	context.Body = string(result)
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
	case http.MethodConnect:
		break
	}
	return http405.MethodNotAllowed(mw, context)
}
