package arp_scanner

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shoriwe/CAPitan/internal/tools"
	"github.com/shoriwe/gplasma"
	"github.com/shoriwe/gplasma/pkg/std/features/importlib"
	"github.com/shoriwe/gplasma/pkg/std/modules/base64"
	"github.com/shoriwe/gplasma/pkg/std/modules/json"
	"github.com/shoriwe/gplasma/pkg/std/modules/regex"
	"github.com/shoriwe/gplasma/pkg/vm"
	"net"
	"time"
)

type Host struct {
	IP  net.IP
	MAC net.HardwareAddr
}

type Engine struct {
	iFaceMac       net.HardwareAddr
	handle         *pcap.Handle
	Hosts          chan Host
	ErrorChannel   chan error
	stopChannel    chan bool
	ethLayer       layers.Ethernet
	arpLayer       layers.ARP
	hostGenerator  func() (bool, string, error)
	VirtualMachine *gplasma.VirtualMachine
	masterContext  *vm.Context
}

func (engine *Engine) arpRequest(host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("invalid IP provided")
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	engine.arpLayer.DstProtAddress = ip.To4()
	serializationError := gopacket.SerializeLayers(buf, opts, &engine.ethLayer, &engine.arpLayer)
	if serializationError != nil {
		return serializationError
	}
	return engine.handle.WritePacketData(buf.Bytes())
}

func (engine *Engine) sendPackets() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	tick := time.Tick(time.Microsecond)
	for {
		select {
		case <-engine.stopChannel:
			// The other goroutine send the stop channel, no need to send a signal to it
			return
		case <-tick:
			hasNext, nextHost, callError := engine.hostGenerator()
			if callError != nil {
				engine.ErrorChannel <- callError
				engine.stopChannel <- true
				return
			}
			if !hasNext {
				// Do not send the signal since we have not check if we received response from all
				return
			}
			arpRequestError := engine.arpRequest(nextHost)
			if arpRequestError != nil {
				engine.ErrorChannel <- arpRequestError
				engine.stopChannel <- true
				return
			}
		}
	}
}

func (engine *Engine) scanPackets() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	packetsSource := gopacket.NewPacketSource(engine.handle, layers.LayerTypeEthernet)
	packets := packetsSource.Packets()

	for {
		select {
		case <-engine.stopChannel:
			return
		case packet, isOpen := <-packets:
			if !isOpen {
				engine.stopChannel <- true
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal(engine.iFaceMac, arp.SourceHwAddress) {
				continue
			}
			engine.Hosts <- Host{
				IP:  arp.SourceProtAddress,
				MAC: arp.SourceHwAddress,
			}
		}
	}
}

func (engine *Engine) mainLoop() {
	go engine.sendPackets()
	go engine.scanPackets()
}

func (engine *Engine) Start() {
	engine.mainLoop()
}

func (engine *Engine) Close() {
	defer tools.RecoverFromChannelClosedWhenWriting()

	engine.stopChannel <- true
	engine.stopChannel <- true
	engine.stopChannel <- true
	engine.stopChannel <- true

	engine.handle.Close()
	close(engine.Hosts)
	close(engine.ErrorChannel)
}

func (engine *Engine) loadVMFeatures() vm.Feature {
	return vm.Feature{
		"LoadHostGenerator": func(context *vm.Context, plasma *vm.Plasma) *vm.Value {
			return plasma.NewFunction(context, true, plasma.BuiltInSymbols(),
				vm.NewBuiltInFunction(1,
					func(self *vm.Value, arguments ...*vm.Value) (*vm.Value, bool) {
						// Validate the object once, the just call HasNext and Next
						foundFunctions := 0
						hasNext, hasNextGetError := arguments[0].Get(engine.VirtualMachine.Plasma, context, vm.HasNext)
						if hasNextGetError == nil {
							foundFunctions++
						}
						next, nextGetError := arguments[0].Get(engine.VirtualMachine.Plasma, context, vm.Next)
						if nextGetError == nil {
							foundFunctions++
						}

						// If the object does not implement Iterator, try to transform it
						if foundFunctions != 2 {
							foundFunctions = 0
							iterFunc, getError := arguments[0].Get(engine.VirtualMachine.Plasma, context, vm.Iter)
							if getError != nil {
								return getError, false
							}
							iter, succeed := engine.VirtualMachine.CallFunction(context, iterFunc)
							if !succeed {
								return iter, false
							}

							hasNext, hasNextGetError = iter.Get(engine.VirtualMachine.Plasma, context, vm.HasNext)
							if hasNextGetError == nil {
								return hasNextGetError, false
							}
							next, nextGetError = iter.Get(engine.VirtualMachine.Plasma, context, vm.Next)
							if nextGetError != nil {
								return nextGetError, false
							}
						}

						engine.hostGenerator = func() (bool, string, error) {
							// Check if the object has next
							hasNextResult, hasNextSucceed := engine.VirtualMachine.CallFunction(context, hasNext)
							if !hasNextSucceed {
								return false, "", errors.New("something goes wrong when calling HasNext function")
							}
							hasNextAsBool, interpretationError := engine.VirtualMachine.QuickGetBool(context, hasNextResult)
							if interpretationError != nil {
								return false, "", errors.New("could not interpret has next as a boolean value")
							}
							if !hasNextAsBool {
								return false, "", nil
							}
							// Return the next host
							nextHostResult, nextHostSucceed := engine.VirtualMachine.CallFunction(context, next)
							if !nextHostSucceed {
								return false, "", errors.New("something wrong happened when calling Next function")
							}
							if !nextHostResult.IsTypeById(vm.StringId) {
								return false, "", errors.New("iterator result is not string")
							}
							return true, nextHostResult.String, nil
						}
						return plasma.GetNone(), true
					},
				),
			)
		},
	}
}

func NewEngine(iFace, scriptSource string) (*Engine, error) {
	iFaceMac, deviceAddress, findError := tools.FindInterfaceIpAndMac(iFace)
	if findError != nil {
		return nil, findError
	}
	handle, openHandleError := pcap.OpenLive(iFace, 65536, true, 0)
	if openHandleError != nil {
		return nil, openHandleError
	}
	engine := &Engine{
		iFaceMac:      iFaceMac,
		handle:        handle,
		Hosts:         make(chan Host, 1000),
		ErrorChannel:  make(chan error, 1),
		stopChannel:   make(chan bool, 100),
		hostGenerator: nil,
		ethLayer: layers.Ethernet{
			SrcMAC:       iFaceMac,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Send to the broadcast
			EthernetType: layers.EthernetTypeARP,
		},
		arpLayer: layers.ARP{
			AddrType:          handle.LinkType(),
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   iFaceMac,
			SourceProtAddress: deviceAddress.To4(),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		},
	}
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
	engine.masterContext = engine.VirtualMachine.NewContext()

	// Load the script

	executionResult, succeed := engine.VirtualMachine.ExecuteMain(scriptSource)
	if !succeed {
		toString, getError := executionResult.Get(engine.VirtualMachine.Plasma, engine.masterContext, vm.ToString)
		if getError != nil {
			return nil, errors.New("unknown error happen when executing script")
		}
		executionErrorAsString, toStringSucceed := engine.VirtualMachine.CallFunction(engine.masterContext, toString)
		if !toStringSucceed {
			return nil, errors.New("unknown error happen when executing script")
		}
		return nil, errors.New(executionErrorAsString.String)
	}

	if engine.hostGenerator == nil {
		return nil, errors.New("host generator never specified")
	}

	return engine, nil
}
