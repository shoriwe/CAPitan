package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/shoriwe/CAPitan/internal/capture"
	"net"
	"os"
	"time"
)

const initScript = `
def packetChecker(packet)
	return False
end

def tcpStreamChecker(contentType, stream)
	return contentType != "unknown"
end

LoadPacketFilter(packetChecker)
LoadTCPStreamFilter(tcpStreamChecker)
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
	initError := engine.InitScript(initScript)
	if initError != nil {
		panic(initError)
	}
	packetChannel, streamChannel, _, startError := engine.Start()
	if startError != nil {
		panic(startError)
	}
	tick := time.Tick(time.Millisecond)
	for {
		for i := 0; i < 1000; i++ {
			select {
			case _, isOpen := <-packetChannel:
				if !isOpen {
					return
				}
			// fmt.Println(packet)
			// if packet.LinkLayer() != nil && packet.NetworkLayer() != nil {
			// 	fmt.Println(packet.LinkLayer().LinkFlow())
			// 	fmt.Println(packet.NetworkLayer().NetworkFlow())
			// }
			case data, isOpen := <-streamChannel:
				if !isOpen {
					return
				}
				fmt.Println(data.Type)
			case <-tick:
				break
			}
		}
	}
}
