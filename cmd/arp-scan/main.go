package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	arp_scanner "github.com/shoriwe/CAPitan/internal/arp-scanner"
	"net"
	"time"
)

const script = `
class Targets
	def Initialize()
		self.current = 0
	end

	def Next()
		host = "192.168.1." + self.current.ToString()
		self.current += 1
		return host
	end

	def HasNext()
		return self.current < 256
	end

	def Iter()
		return self
	end
end

LoadHostGenerator(Targets())
`

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	var targetDevice string
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.Equal(net.ParseIP("192.168.1.33")) { // You should change this for the IP of your machine in the network you want
				targetDevice = device.Name
				break
			}
		}
	}
	if targetDevice == "" {
		panic("no device found")
	}

	engine, engineCreationError := arp_scanner.NewEngine(targetDevice, script)
	if engineCreationError != nil {
		panic(engineCreationError)
	}

	engine.Start()
	defer engine.Close()

	stopChannel := make(chan bool, 1)

	go func() {
		time.Sleep(5 * time.Second)
		stopChannel <- true
	}()

	tick := time.Tick(time.Microsecond)
	foundHosts := map[string]struct{}{}
mainLoop:
	for {
		select {
		case <-stopChannel:
			break mainLoop
		case engineErr := <-engine.ErrorChannel:
			panic(engineErr)
		case host, isOpen := <-engine.Hosts:
			if isOpen {
				if _, found := foundHosts[host.IP.String()]; !found {
					fmt.Println(host.IP.String(), "->", host.MAC.String())
					foundHosts[host.IP.String()] = struct{}{}
				}
			} else {
				break mainLoop
			}
		case <-tick:
			break
		}
	}
	close(stopChannel)
	fmt.Println("Scan completed")
	fmt.Println("If it does not close, don't worry, the handle is waiting to a nice moment to acquire the mutex")
}
