package capture

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/shoriwe/gplasma"
	errors2 "github.com/shoriwe/gplasma/pkg/errors"
	"github.com/shoriwe/gplasma/pkg/std/features/importlib"
	"github.com/shoriwe/gplasma/pkg/std/modules/base64"
	"github.com/shoriwe/gplasma/pkg/std/modules/json"
	"github.com/shoriwe/gplasma/pkg/std/modules/regex"
	"github.com/shoriwe/gplasma/pkg/vm"
	"io"
	"os"
	"reflect"
	"sync"
	"time"
)

const (
	defaultSnapLen = 65536
)

var (
	FailedToConvertErrorToString = errors.New("failed to convert to string the error received")
)

func engineFeatures(engine *Engine) vm.Feature {
	return vm.Feature{
		"LoadPacketFilter": func(context *vm.Context, plasma *vm.Plasma) *vm.Value {
			return plasma.NewFunction(context, true, plasma.BuiltInSymbols(),
				vm.NewBuiltInFunction(1,
					func(self *vm.Value, arguments ...*vm.Value) (*vm.Value, bool) {
						engine.packetFilter = func(packet gopacket.Packet) (bool, error) {
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
						engine.tcpStreamFilter = func(tcpStream Data) (bool, error) {
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

type securedFileSystem struct {
}

func (s *securedFileSystem) ChangeDirectoryRelative(_ string) *errors2.Error {
	return nil
}

func (s *securedFileSystem) ChangeDirectoryFullPath(_ string) *errors2.Error {
	return nil
}

func (s *securedFileSystem) ChangeDirectoryToFileLocation(_ string) *errors2.Error {
	return nil
}

func (s *securedFileSystem) ResetPath() {
	return
}

func (s *securedFileSystem) OpenRelative(_ string) (io.ReadSeekCloser, error) {
	return nil, nil
}

func (s *securedFileSystem) ExistsRelative(_ string) bool {
	return false
}

func (s *securedFileSystem) ListDirectory() ([]string, error) {
	return nil, nil
}

func (s *securedFileSystem) AbsolutePwd() string {
	return ""
}

func (s *securedFileSystem) RelativePwd() string {
	return ""
}

type tcpStreamFactory struct {
	TCPStreamChannel chan Data
}

func (t *tcpStreamFactory) New(_, _ gopacket.Flow) tcpassembly.Stream {
	stream := tcpreader.NewReaderStream()
	go func(s io.Reader) {
		defer func() {
			if r := recover(); r != nil {

			}
		}()
		chunk := bytes.NewBuffer(nil)
		tempChunk := make([]byte, defaultSnapLen)
		for {
			numberOfBytesRead, readError := s.Read(tempChunk)
			if readError == io.EOF {
				break
			}
			chunk.Write(tempChunk[:numberOfBytesRead])
		}
		data, detectionError := DetectChunkFormat(chunk.Bytes())
		if detectionError == nil {
			for _, d := range data {
				t.TCPStreamChannel <- d
			}
		}
	}(&stream)
	return &stream
}

type Engine struct {
	controlMutex    *sync.Mutex
	paused          bool
	resume          chan bool
	packetFilter    func(packet gopacket.Packet) (bool, error)
	tcpStreamFilter func(bytes Data) (bool, error)
	VirtualMachine  *gplasma.VirtualMachine
	machineContext  *vm.Context
	// Interface Configuration
	Promiscuous      bool
	NetworkInterface string
	PcapFile         *os.File
	handle           *pcap.Handle
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

func (engine *Engine) mainLoop(outPacketChannel, filterPacketChannel chan gopacket.Packet, outTCPStreamChannel, filterTCPStreamChannel chan Data) {
	if outPacketChannel == filterPacketChannel {
		defer close(filterPacketChannel)
	}
	if outTCPStreamChannel == filterTCPStreamChannel {
		defer close(filterTCPStreamChannel)
	}
	source := gopacket.NewPacketSource(engine.handle, engine.handle.LinkType())
	packets := source.Packets()
	defer close(packets)

	streamFactory := &tcpStreamFactory{
		TCPStreamChannel: filterTCPStreamChannel,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = 500
	assembler.MaxBufferedPagesTotal = 100000

	tick := time.Tick(time.Second * 2)

	for {
		select {
		case packet, isOpen := <-packets:
			if isOpen {
				if packet != nil {
					if packet.NetworkLayer() != nil && packet.TransportLayer() != nil {
						if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
							assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().(*layers.TCP), packet.Metadata().Timestamp)
						}
					}
					filterPacketChannel <- packet
				}
			}
		case <-tick:
			assembler.FlushOlderThan(time.Now().Add(time.Second * -5))
		}
	}
}

func (engine *Engine) Start() (chan gopacket.Packet, chan Data, chan error, error) {
	var openError error
	if engine.NetworkInterface != "" {
		engine.handle, openError = pcap.OpenLive(engine.NetworkInterface, defaultSnapLen, engine.Promiscuous, 0)
	} else if engine.PcapFile != nil {
		engine.handle, openError = pcap.OpenOfflineFile(engine.PcapFile)
	}
	if openError != nil {
		return nil, nil, nil, openError
	}
	packetChannel := make(chan gopacket.Packet, 1000)
	streamChannel := make(chan Data, 1000)

	var (
		filterPackedChannel = packetChannel
		filterStreamChannel = streamChannel
	)
	if engine.packetFilter != nil {
		filterPackedChannel = make(chan gopacket.Packet, 1000)
	}
	if engine.tcpStreamFilter != nil {
		filterStreamChannel = make(chan Data, 1000)
	}
	errorChannel := make(chan error)
	if engine.packetFilter != nil && engine.tcpStreamFilter != nil {
		go func() {
			defer close(packetChannel)
			defer close(streamChannel)
			defer close(filterPackedChannel)
			defer close(filterStreamChannel)

			tick := time.Tick(time.Second * 2)
			for {
				select {
				case <-tick:
					for i := 0; i < 1000; i++ {
						select {
						case packet, isOpen := <-filterPackedChannel:
							if isOpen {
								succeed, err := engine.packetFilter(packet)
								if err != nil {
									errorChannel <- err
									return
								}
								if succeed {
									packetChannel <- packet
								}
							} else {
								return
							}
						default:
							break
						}
						select {
						case stream, isOpen := <-filterStreamChannel:
							if isOpen {
								succeed, err := engine.tcpStreamFilter(stream)
								if err != nil {
									errorChannel <- err
									return
								}
								if succeed {
									streamChannel <- stream
								}
							} else {
								return
							}
						default:
							break
						}
					}
				}
			}
		}()
	} else if engine.packetFilter != nil {
		go func() {
			defer close(packetChannel)
			defer close(streamChannel)
			defer close(filterPackedChannel)
			defer close(filterStreamChannel)

			tick := time.Tick(time.Second * 2)
			for {
				select {
				case <-tick:
					for i := 0; i < 1000; i++ {
						select {
						case packet, isOpen := <-filterPackedChannel:
							if isOpen {
								succeed, err := engine.packetFilter(packet)
								if err != nil {
									errorChannel <- err
									return
								}
								if succeed {
									packetChannel <- packet
								}
							} else {
								return
							}
						default:
							break
						}
					}
				}
			}
		}()
	} else if engine.tcpStreamFilter != nil {
		go func() {
			defer close(packetChannel)
			defer close(streamChannel)
			defer close(filterPackedChannel)
			defer close(filterStreamChannel)

			tick := time.Tick(time.Second * 2)
			for {
				select {
				case <-tick:
					for i := 0; i < 1000; i++ {
						select {
						case stream, isOpen := <-filterStreamChannel:
							if isOpen {
								succeed, err := engine.tcpStreamFilter(stream)
								if err != nil {
									errorChannel <- err
									return
								}
								if succeed {
									streamChannel <- stream
								}
							} else {
								return
							}
						default:
							break
						}
					}
				}
			}
		}()
	}
	go engine.mainLoop(packetChannel, filterPackedChannel, streamChannel, filterStreamChannel)
	return packetChannel, streamChannel, errorChannel, nil
}

func (engine *Engine) Close() {
	engine.handle.Close()
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
			"LinkFlow": map[string]interface{}{
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
			"LinkFlow": map[string]interface{}{
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

func NewEngine(netInterface string) *Engine {
	engine := &Engine{
		controlMutex:     new(sync.Mutex),
		resume:           make(chan bool, 1),
		paused:           false,
		NetworkInterface: netInterface,
		packetFilter:     nil,
		tcpStreamFilter:  nil,
		VirtualMachine:   nil,
		Promiscuous:      false,
		PcapFile:         nil,
		handle:           nil,
	}
	engine.VirtualMachine = gplasma.NewVirtualMachine()
	engine.VirtualMachine.LoadFeature(engineFeatures(engine))
	importer := importlib.NewImporter()
	importer.LoadModule(json.JSON)
	importer.LoadModule(base64.Base64)
	importer.LoadModule(regex.Regex)
	engine.VirtualMachine.LoadFeature(importer.Result(&securedFileSystem{}, &securedFileSystem{}))
	engine.machineContext = engine.VirtualMachine.NewContext()
	return engine
}
