package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/shoriwe/CAPitan/internal/capture"
	"net"
	"os"
)

const initScript = `
def packetChecker(packet)
	if packet.Contains("TransportLayer")
		println(packet.Index("TransportLayer"))
	end
	return False
end

# def tcpStreamChecker(stream)
# 	println(stream.ToString())
# 	return False
# end


LoadPacketFilter(packetChecker)
# LoadTCPStreamFilter(tcpStreamChecker)
`

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	var targetDevice string
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.Equal(net.ParseIP("192.168.1.11")) { // You should change this for the IP of your machine in the network you want
				targetDevice = device.Name
				break
			}
		}
	}
	if targetDevice == "" {
		panic("no device found")
	}
	engine := capture.NewEngine(targetDevice)
	engine.VirtualMachine.Stdout = os.Stdout
	engine.Promiscuous = true
	succeed, initError := engine.InitScript(initScript)
	if initError != nil {
		panic(initError)
	}
	if !succeed {
		panic("Failed to init with script")
	}
	outputChannel, startError := engine.Start()
	if startError != nil {
		panic(startError)
	}
	for output := range outputChannel {
		if output.Stream != nil {
			fmt.Println(string(output.Stream))
		}
		if output.Packet != nil {
			fmt.Println(output.Packet)
		}
		if output.Error != nil {
			panic(output.Error)
		}
		if output.Completed {
			break
		}
	}
}
