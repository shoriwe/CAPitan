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

def tcpStreamChecker(stream)
	println(stream.ToString())
	return True
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
	// succeed, initError := engine.InitScript(initScript)
	// if initError != nil {
	// 	panic(initError)
	// }
	// if !succeed {
	// 	panic("Failed to init with script")
	// }
	packetChannel, streamChannel, startError := engine.Start()
	if startError != nil {
		panic(startError)
	}
	tick := time.Tick(time.Millisecond)
	for {
		<-tick
	captureLoop:
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
			default:
				break captureLoop
			}
		}
	streamLoop:
		for i := 0; i < 1000; i++ {
			select {
			case stream, isOpen := <-streamChannel:
				if !isOpen {
					return
				}
				fmt.Println(string(stream))
			default:
				break streamLoop
			}
		}
	}
}
