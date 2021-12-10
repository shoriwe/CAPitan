package tools

import (
	"errors"
	"fmt"
	"github.com/google/gopacket/pcap"
	errors2 "github.com/shoriwe/gplasma/pkg/errors"
	"io"
	"net"
	"strings"
)

type SecuredFileSystem struct {
}

func (s *SecuredFileSystem) ChangeDirectoryRelative(_ string) *errors2.Error {
	return nil
}

func (s *SecuredFileSystem) ChangeDirectoryFullPath(_ string) *errors2.Error {
	return nil
}

func (s *SecuredFileSystem) ChangeDirectoryToFileLocation(_ string) *errors2.Error {
	return nil
}

func (s *SecuredFileSystem) ResetPath() {
	return
}

func (s *SecuredFileSystem) OpenRelative(_ string) (io.ReadSeekCloser, error) {
	return nil, nil
}

func (s *SecuredFileSystem) ExistsRelative(_ string) bool {
	return false
}

func (s *SecuredFileSystem) ListDirectory() ([]string, error) {
	return nil, nil
}

func (s *SecuredFileSystem) AbsolutePwd() string {
	return ""
}

func (s *SecuredFileSystem) RelativePwd() string {
	return ""
}

func RecoverFromChannelClosedWhenWriting() {
	if r := recover(); r != nil {
		fmt.Println(r)
		// TODO: Then what?
	}
}

func FindInterfaceIpAndMac(iFace string) (net.HardwareAddr, net.IP, error) {
	// TODO: Check if this solution is cross platform
	devices, findError := pcap.FindAllDevs()
	if findError != nil {
		return nil, nil, findError
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
		return nil, nil, errors.New("device not found")
	}

	var deviceAddress net.IP = nil
	for _, address := range selectedDevice.Addresses {
		deviceAddress = address.IP
	}
	if deviceAddress == nil {
		return nil, nil, errors.New("not available addresses")
	}

	netInterfaces, getError := net.Interfaces()
	if getError != nil {
		return nil, nil, getError
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
		return nil, nil, errors.New("could not find mac address")
	}

	return deviceMac, deviceAddress, nil
}
