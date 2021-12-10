package packet

import (
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"github.com/shoriwe/gplasma/pkg/compiler/lexer"
	"github.com/shoriwe/gplasma/pkg/compiler/parser"
	"github.com/shoriwe/gplasma/pkg/reader"
)

func checkInterfaceCaptureInputArguments(mw *middleware.Middleware, context *middleware.Context, captureName, interfaceName, description, script string) (bool, string) {
	if len(script) > 0 {
		if tools.CheckFilledWithWhiteSpace.MatchString(script) {
			return false, "script provided but completely filled with white spaces"
		}
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
	if len(interfaceName) == 0 {
		return false, "no interface provided"
	}
	// Check the capture is a valid string
	if len(captureName) == 0 {
		return false, "no capture name provided"
	}
	// Check the description is a valid string
	if len(description) == 0 {
		return false, "no description provided"
	}

	// Check the interface name is a valid string
	if tools.CheckFilledWithWhiteSpace.MatchString(interfaceName) {
		return false, "no interface provided"
	}
	// Check the capture is a valid string
	if tools.CheckFilledWithWhiteSpace.MatchString(captureName) {
		return false, "no capture name provided"
	}
	// Check the description is a valid string
	if tools.CheckFilledWithWhiteSpace.MatchString(description) {
		return false, "no description provided"
	}
	return true, "succeed"
}

func Captures(mw *middleware.Middleware, context *middleware.Context) bool {
	switch context.Request.FormValue(actions.Action) {
	case actions.New:
		return newInterfaceCapture(mw, context)
	case actions.Import:
		return importCapture(mw, context)
	case actions.Start:
		return startInterfaceBasedCapture(mw, context)
	case actions.View:
		return viewCapture(mw, context)
	case actions.Download:
		return downloadCapture(mw, context)
	}
	return listCaptures(mw, context)
}
