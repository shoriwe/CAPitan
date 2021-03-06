package capture

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/gplasma"
	"github.com/shoriwe/gplasma/pkg/std/features/importlib"
	"github.com/shoriwe/gplasma/pkg/std/modules/base64"
	"github.com/shoriwe/gplasma/pkg/std/modules/json"
	"github.com/shoriwe/gplasma/pkg/std/modules/regex"
	"github.com/shoriwe/gplasma/pkg/vm"
	"io"
	"os"
	"reflect"
	"time"
)

var (
	FailedToConvertErrorToString = errors.New("failed to convert to string the error received")
)

type tcpStreamFactory struct {
	TCPStreamChannel chan Data
}

type tcpStreamBuffer struct {
	bytes.Buffer
	outputChannel chan Data
}

func (t *tcpStreamBuffer) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		_, _ = t.Write(r.Bytes)
	}
}

func (t *tcpStreamBuffer) ReassemblyComplete() {
	extractedChunks, extractionError := DetectChunkFormat(t.Bytes())
	if extractionError == nil {
		for _, dataChunk := range extractedChunks {
			t.outputChannel <- dataChunk
		}
	}
}

func (t *tcpStreamFactory) New(_, _ gopacket.Flow) tcpassembly.Stream {
	stream := &tcpStreamBuffer{
		Buffer:        bytes.Buffer{},
		outputChannel: t.TCPStreamChannel,
	}
	return stream
}

type Engine struct {
	PacketFilter       func(packet gopacket.Packet) (bool, error)
	TCPStreamFilter    func(bytes Data) (bool, error)
	VirtualMachine     *gplasma.VirtualMachine
	machineContext     *vm.Context
	ErrorChannel       chan error
	stopChannel        chan bool
	Packets            chan gopacket.Packet
	TCPStreams         chan Data
	packetsToFilter    chan gopacket.Packet
	tcpStreamsToFilter chan Data
	// Interface Configuration (This will be setup from the outside)
	Promiscuous      bool
	NetworkInterface string
	PcapFile         *os.File
	handle           *pcap.Handle

	pcapContents []byte
	pcapDumpFile *os.File
}

func (engine *Engine) loadVMFeatures() vm.Feature {
	return vm.Feature{
		"LoadPacketFilter": func(context *vm.Context, plasma *vm.Plasma) *vm.Value {
			return plasma.NewFunction(context, true, plasma.BuiltInSymbols(),
				vm.NewBuiltInFunction(1,
					func(self *vm.Value, arguments ...*vm.Value) (*vm.Value, bool) {
						engine.PacketFilter = func(packet gopacket.Packet) (bool, error) {
							result, succeed := engine.VirtualMachine.Plasma.CallFunction(
								engine.machineContext,
								arguments[0],
								interpretToPlasmaMap(engine.machineContext, engine.VirtualMachine.Plasma, TransformPacketToMap(packet)))
							if !succeed {
								toString, getError := result.Get(engine.VirtualMachine.Plasma, engine.machineContext, vm.ToString)
								if getError != nil {
									return false, FailedToConvertErrorToString
								}
								var errorAsString *vm.Value
								errorAsString, succeed = engine.VirtualMachine.CallFunction(engine.machineContext, toString)
								if !succeed {
									return false, FailedToConvertErrorToString
								}
								return false, errors.New(errorAsString.String)
							}
							output, asBoolError := engine.VirtualMachine.QuickGetBool(engine.machineContext, result)
							if asBoolError != nil {
								toString, getError := asBoolError.Get(engine.VirtualMachine.Plasma, engine.machineContext, vm.ToString)
								if getError != nil {
									return false, FailedToConvertErrorToString
								}
								var errorAsString *vm.Value
								errorAsString, succeed = engine.VirtualMachine.CallFunction(engine.machineContext, toString)
								if !succeed {
									return false, FailedToConvertErrorToString
								}
								return false, errors.New(errorAsString.String)
							}
							return output, nil
						}
						return plasma.GetNone(), true
					},
				),
			)
		},
		"LoadTCPStreamFilter": func(context *vm.Context, plasma *vm.Plasma) *vm.Value {
			return plasma.NewFunction(context, true, plasma.BuiltInSymbols(),
				vm.NewBuiltInFunction(1,
					func(self *vm.Value, arguments ...*vm.Value) (*vm.Value, bool) {
						engine.TCPStreamFilter = func(tcpStream Data) (bool, error) {
							result, succeed := engine.VirtualMachine.Plasma.CallFunction(
								engine.machineContext,
								arguments[0],
								engine.VirtualMachine.NewString(engine.machineContext, false, tcpStream.Type),
								engine.VirtualMachine.NewBytes(engine.machineContext, false, tcpStream.Content),
							)
							if !succeed {
								toString, getError := result.Get(engine.VirtualMachine.Plasma, engine.machineContext, vm.ToString)
								if getError != nil {
									return false, FailedToConvertErrorToString
								}
								var errorAsString *vm.Value
								errorAsString, succeed = engine.VirtualMachine.CallFunction(engine.machineContext, toString)
								if !succeed {
									return false, FailedToConvertErrorToString
								}
								return false, errors.New(errorAsString.String)
							}
							output, asBoolError := engine.VirtualMachine.QuickGetBool(engine.machineContext, result)
							if asBoolError != nil {
								toString, getError := asBoolError.Get(engine.VirtualMachine.Plasma, engine.machineContext, vm.ToString)
								if getError != nil {
									return false, FailedToConvertErrorToString
								}
								var errorAsString *vm.Value
								errorAsString, succeed = engine.VirtualMachine.CallFunction(engine.machineContext, toString)
								if !succeed {
									return false, FailedToConvertErrorToString
								}
								return false, errors.New(errorAsString.String)
							}
							return output, nil
						}
						return plasma.GetNone(), true
					},
				),
			)
		},
	}
}

func (engine *Engine) InitScript(script string) error {
	result, succeed := engine.VirtualMachine.ExecuteMain(script)
	if !succeed {
		toString, getError := result.Get(engine.VirtualMachine.Plasma, engine.VirtualMachine.BuiltInContext, vm.ToString)
		if getError != nil {
			return FailedToConvertErrorToString
		}
		asString, callSucceed := engine.VirtualMachine.CallFunction(engine.VirtualMachine.BuiltInContext, toString)
		if !callSucceed {
			return FailedToConvertErrorToString
		}
		return errors.New(asString.String)
	}
	return nil
}

func (engine *Engine) dump(pcapDump *pcapgo.Writer, packet gopacket.Packet) {
	_ = pcapDump.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}

func (engine *Engine) mainLoop() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	source := gopacket.NewPacketSource(engine.handle, engine.handle.LinkType())
	packets := source.Packets()

	streamFactory := &tcpStreamFactory{
		TCPStreamChannel: engine.tcpStreamsToFilter,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = 500
	assembler.MaxBufferedPagesTotal = 100000

	pcapDump := pcapgo.NewWriter(engine.pcapDumpFile)
	writeError := pcapDump.WriteFileHeader(65536, engine.handle.LinkType())
	if writeError != nil {
		engine.ErrorChannel <- writeError
		return
	}

	tick := time.Tick(time.Second)

	for {
		select {
		case <-engine.stopChannel:
			return
		case packet, isOpen := <-packets:
			if isOpen {
				if packet != nil {
					go engine.dump(pcapDump, packet)
					if packet.NetworkLayer() != nil && packet.TransportLayer() != nil && packet.ApplicationLayer() != nil {
						if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
							assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().(*layers.TCP), packet.Metadata().Timestamp)
						}
						engine.packetsToFilter <- packet
					}
				}
			}
		case <-tick:
			assembler.FlushOlderThan(time.Now().Add(time.Second * -5))
		}
	}
}

func (engine *Engine) filterStreamsAndPackets() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	tick := time.Tick(time.Second)
	for {
		select {
		case <-engine.stopChannel:
			return
		case <-tick:
			for i := 0; i < 1000; i++ {
				select {
				case packet, isOpen := <-engine.packetsToFilter:
					if isOpen {
						succeed, err := engine.PacketFilter(packet)
						if err != nil {
							engine.ErrorChannel <- err
							engine.stopChannel <- true
							return
						}
						if succeed {
							engine.Packets <- packet
						}
					} else {
						engine.stopChannel <- true
						return
					}
				default:
					break
				}
				select {
				case stream, isOpen := <-engine.tcpStreamsToFilter:
					if isOpen {
						succeed, err := engine.TCPStreamFilter(stream)
						if err != nil {
							engine.ErrorChannel <- err
							engine.stopChannel <- true
							return
						}
						if succeed {
							engine.TCPStreams <- stream
						}
					} else {
						engine.stopChannel <- true
						return
					}
				default:
					break
				}
			}
		}
	}
}

func (engine *Engine) filterPacketsOnly() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	tick := time.Tick(time.Microsecond * 500)
	for {
		select {
		case <-engine.stopChannel:
			return
		case <-tick:
		filterLoop:
			for i := 0; i < 1000; i++ {
				select {
				case packet, isOpen := <-engine.packetsToFilter:
					if isOpen {
						succeed, err := engine.PacketFilter(packet)
						if err != nil {
							engine.ErrorChannel <- err
							engine.stopChannel <- true
							return
						}
						if succeed {
							engine.Packets <- packet
						}
					} else {
						engine.stopChannel <- true
						return
					}
				default:
					break filterLoop
				}
			}
		}
	}
}

func (engine *Engine) filterStreamsOnly() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	tick := time.Tick(time.Second)
	for {
		select {
		case <-engine.stopChannel:
			return
		case <-tick:
		filterLoop:
			for i := 0; i < 1000; i++ {
				select {
				case stream, isOpen := <-engine.tcpStreamsToFilter:
					if isOpen {
						succeed, err := engine.TCPStreamFilter(stream)
						if err != nil {
							engine.ErrorChannel <- err
							engine.stopChannel <- true
							return
						}
						if succeed {
							engine.TCPStreams <- stream
						}
					} else {
						engine.stopChannel <- true
						return
					}
				default:
					break filterLoop
				}
			}
		}
	}
}

func (engine *Engine) Start() error {
	if engine.PacketFilter != nil {
		engine.packetsToFilter = make(chan gopacket.Packet, 1000)
	}
	if engine.TCPStreamFilter != nil {
		engine.tcpStreamsToFilter = make(chan Data, 1000)
	}
	if engine.PacketFilter != nil && engine.TCPStreamFilter != nil {
		go engine.filterStreamsAndPackets()
	} else if engine.PacketFilter != nil {
		go engine.filterPacketsOnly()
	} else if engine.TCPStreamFilter != nil {
		go engine.filterStreamsOnly()
	}
	go engine.mainLoop()
	return nil
}

/*
	DumpPcap: This function should always be called before engine.Close()
*/
func (engine *Engine) DumpPcap() []byte {
	_ = engine.pcapDumpFile.Close()
	file, openError := os.Open(engine.pcapDumpFile.Name())
	if openError != nil {
		panic(openError) // Probably the file got deleted before
	}
	defer file.Close()
	contents, readError := io.ReadAll(file)
	if readError != nil {
		panic(readError) // What happen
	}
	return contents
}

func (engine *Engine) Close() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	engine.stopChannel <- true
	engine.stopChannel <- true
	engine.stopChannel <- true
	engine.stopChannel <- true

	_ = engine.pcapDumpFile.Close()
	_ = os.Remove(engine.pcapDumpFile.Name())
	engine.handle.Close()
	close(engine.Packets)
	close(engine.TCPStreams)
	close(engine.packetsToFilter)
	close(engine.tcpStreamsToFilter)
}

func interpretToPlasmaMap(context *vm.Context, p *vm.Plasma, i interface{}) *vm.Value {
	switch i.(type) {
	case []byte:
		return p.NewBytes(context, false, i.([]byte))
	case bool:
		return p.InterpretAsBool(i.(bool))
	case nil:
		return p.GetNone()
	case string:
		return p.NewString(context, false, i.(string))
	case float64:
		return p.NewFloat(context, false, i.(float64))
	case int:
		return p.NewInteger(context, false, int64(i.(int)))
	case map[string]interface{}:
		result := p.NewHashTable(context, false)
		for key, value := range i.(map[string]interface{}) {
			p.HashIndexAssign(context, result, p.NewString(context, false, key), interpretToPlasmaMap(context, p, value))
		}
		return result
	case []interface{}:
		var elements []*vm.Value
		for _, element := range i.([]interface{}) {
			elements = append(elements, interpretToPlasmaMap(context, p, element))
		}
		return p.NewArray(context, false, elements)
	default:
		panic(reflect.TypeOf(i))
	}
}

func TransformPacketToMap(packet gopacket.Packet) map[string]interface{} {
	result := map[string]interface{}{
		"Data": packet.Data(),
		"Dump": packet.Dump(),
	}
	if packet.Metadata() == nil {
		result["Metadata"] = map[string]interface{}{
			"Length":         0,
			"CaptureLength":  0,
			"Truncated":      false,
			"InterfaceIndex": 0,
		}
	} else {
		result["Metadata"] = map[string]interface{}{
			"Length":         packet.Metadata().Length,
			"CaptureLength":  packet.Metadata().CaptureLength,
			"Truncated":      packet.Metadata().Truncated,
			"InterfaceIndex": packet.Metadata().InterfaceIndex,
		}
	}
	if packet.TransportLayer() == nil {
		result["TransportLayer"] = map[string]interface{}{
			"LayerType":     "",
			"LayerPayload":  nil,
			"LayerContents": nil,
			"TransportFlow": map[string]interface{}{
				"String":       "",
				"Src":          "",
				"Dst":          "",
				"EndpointType": "",
			},
		}
	} else {
		result["TransportLayer"] = map[string]interface{}{
			"LayerType":     packet.TransportLayer().LayerType().String(),
			"LayerPayload":  packet.TransportLayer().LayerPayload(),
			"LayerContents": packet.TransportLayer().LayerContents(),
			"TransportFlow": map[string]interface{}{
				"String":       packet.TransportLayer().TransportFlow().String(),
				"Src":          packet.TransportLayer().TransportFlow().Src().String(),
				"Dst":          packet.TransportLayer().TransportFlow().Dst().String(),
				"EndpointType": packet.TransportLayer().TransportFlow().EndpointType().String(),
			},
		}
	}
	if packet.ApplicationLayer() == nil {
		result["ApplicationLayer"] = map[string]interface{}{
			"LayerType":     "",
			"LayerPayload":  nil,
			"LayerContents": nil,
			"Payload":       nil,
		}
	} else {
		result["ApplicationLayer"] = map[string]interface{}{
			"LayerType":     packet.ApplicationLayer().LayerType().String(),
			"LayerPayload":  packet.ApplicationLayer().LayerPayload(),
			"LayerContents": packet.ApplicationLayer().LayerContents(),
			"Payload":       packet.ApplicationLayer().Payload(),
		}
	}
	if packet.NetworkLayer() == nil {
		result["NetworkLayer"] = map[string]interface{}{
			"LayerType":     "",
			"LayerPayload":  nil,
			"LayerContents": nil,
			"NetworkFlow": map[string]interface{}{
				"Src":          "",
				"Dst":          "",
				"String":       "",
				"EndpointType": "",
			},
		}
	} else {
		result["NetworkLayer"] = map[string]interface{}{
			"LayerType":     packet.NetworkLayer().LayerType().String(),
			"LayerPayload":  packet.NetworkLayer().LayerPayload(),
			"LayerContents": packet.NetworkLayer().LayerContents(),
			"NetworkFlow": map[string]interface{}{
				"Src":          packet.NetworkLayer().NetworkFlow().Src().String(),
				"Dst":          packet.NetworkLayer().NetworkFlow().Dst().String(),
				"String":       packet.NetworkLayer().NetworkFlow().String(),
				"EndpointType": packet.NetworkLayer().NetworkFlow().EndpointType().String(),
			},
		}
	}
	if packet.LinkLayer() == nil {
		result["LinkLayer"] = map[string]interface{}{
			"LayerType":     "",
			"LayerPayload":  nil,
			"LayerContents": nil,
			"LinkFlow": map[string]interface{}{
				"Src":          "",
				"Dst":          "",
				"String":       "",
				"EndpointType": "",
			},
		}
	} else {
		result["LinkLayer"] = map[string]interface{}{
			"LayerType":     packet.LinkLayer().LayerType().String(),
			"LayerPayload":  packet.LinkLayer().LayerPayload(),
			"LayerContents": packet.LinkLayer().LayerContents(),
			"LinkFlow": map[string]interface{}{
				"Src":          packet.LinkLayer().LinkFlow().Src().String(),
				"Dst":          packet.LinkLayer().LinkFlow().Dst().String(),
				"String":       packet.LinkLayer().LinkFlow().String(),
				"EndpointType": packet.LinkLayer().LinkFlow().EndpointType().String(),
			},
		}
	}
	if packet.ErrorLayer() == nil {
		result["ErrorLayer"] = map[string]interface{}{
			"LayerType":     "",
			"LayerPayload":  nil,
			"LayerContents": nil,
			"ErrorFlow":     "",
		}
	} else if packet.ErrorLayer().Error() == nil {
		result["ErrorLayer"] = map[string]interface{}{
			"LayerType":     packet.ErrorLayer().LayerType().String(),
			"LayerPayload":  packet.ErrorLayer().LayerPayload(),
			"LayerContents": packet.ErrorLayer().LayerContents(),
			"ErrorFlow":     nil,
		}
	} else {
		result["ErrorLayer"] = map[string]interface{}{
			"LayerType":     packet.ErrorLayer().LayerType().String(),
			"LayerPayload":  packet.ErrorLayer().LayerPayload(),
			"LayerContents": packet.ErrorLayer().LayerContents(),
			"ErrorFlow":     "",
		}
	}
	return result
}

func newEngine() (*Engine, error) {
	engine := &Engine{
		PacketFilter:    nil,
		TCPStreamFilter: nil,
		Packets:         make(chan gopacket.Packet, 1000),
		TCPStreams:      make(chan Data, 1000),
		stopChannel:     make(chan bool, 100),
		pcapContents:    nil,
		VirtualMachine:  nil,
		Promiscuous:     false,
		PcapFile:        nil,
		handle:          nil,
	}
	engine.packetsToFilter = engine.Packets
	engine.tcpStreamsToFilter = engine.TCPStreams
	engine.VirtualMachine = gplasma.NewVirtualMachine()
	engine.VirtualMachine.Stdin = &bytes.Buffer{}
	engine.VirtualMachine.Stdout = &bytes.Buffer{}
	engine.VirtualMachine.Stderr = &bytes.Buffer{}
	engine.VirtualMachine.LoadFeature(engine.loadVMFeatures())
	importer := importlib.NewImporter()
	importer.LoadModule(json.JSON)
	importer.LoadModule(base64.Base64)
	importer.LoadModule(regex.Regex)
	engine.VirtualMachine.LoadFeature(importer.Result(&tools.SecuredFileSystem{}, &tools.SecuredFileSystem{}))
	engine.machineContext = engine.VirtualMachine.NewContext()

	tempPcapFile, createError := os.CreateTemp("", "*.pcap")
	if createError != nil {
		return nil, createError
	}
	engine.pcapDumpFile = tempPcapFile
	return engine, nil
}

func NewEngineWithInterface(netInterface string) (*Engine, error) {
	engine, creationError := newEngine()
	if creationError != nil {
		return nil, creationError
	}
	engine.NetworkInterface = netInterface
	handle, openError := pcap.OpenLive(engine.NetworkInterface, 65536, engine.Promiscuous, 0)
	if openError != nil {
		return nil, openError
	}
	engine.handle = handle
	return engine, nil
}

func NewEngineWithFile(file *os.File) (*Engine, error) {
	engine, creationError := newEngine()
	if creationError != nil {
		return nil, creationError
	}
	engine.PcapFile = file
	handle, openError := pcap.OpenOfflineFile(engine.PcapFile)
	if openError != nil {
		return nil, openError
	}
	engine.handle = handle
	return engine, nil
}
