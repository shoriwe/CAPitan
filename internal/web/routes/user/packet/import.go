package packet

import (
	"crypto/md5"
	"github.com/google/gopacket"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/web/base"
	"github.com/shoriwe/CAPitan/internal/web/http405"
	"github.com/shoriwe/CAPitan/internal/web/middleware"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"io"
	"net/http"
	"os"
	"time"
)

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

	isValid, _ := checkInterfaceCaptureInputArguments(mw, context, captureName, "interface", description, script)

	if !isValid {
		return false
	}

	if !mw.ReserveUserCaptureName(context.Request, context.User.Username, captureName) {
		return false
	}
	defer mw.RemoveReservedCaptureName(context.Request, context.User.Username, captureName)

	engine, creationError := capture.NewEngineWithFile(file)
	if creationError != nil {
		go mw.LogError(context.Request, creationError)
		return false
	}
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
