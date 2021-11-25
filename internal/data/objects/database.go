package objects

import "time"

type (
	User struct {
		Id                     uint
		Username               string
		PasswordHash           string
		SecurityQuestion       string
		SecurityQuestionAnswer string
		IsAdmin                bool
		IsEnabled              bool
		PasswordExpirationDate time.Time
	}
	ARPSpoofPermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
	ARPScanPermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
	CapturePermission struct {
		Id        uint
		UsersId   uint
		Interface string
	}
	CaptureSession struct {
		Id           uint
		UsersId      uint
		Interface    string
		Name         string
		Description  string
		Started      time.Time
		Ended        time.Time
		Pcap         []byte
		FilterScript []byte
	}
	TCPStream struct {
		Id               uint
		CaptureSessionId uint
		StartingPacketId uint
		Contents         []byte
	}
	Packet struct {
		Id                  uint
		CaptureSessionsId   uint
		TransportLayersId   uint
		InternetLayersId    uint
		ApplicationLayersId uint
		SourceAddress       string
		SourcePort          uint
		SourceMac           string
		DestinationAddress  string
		DestinationPort     uint
		DestinationMac      string
		Contents            []byte
	}
	TransportLayer struct {
		Id   uint
		Name string
	}
	ApplicationLater struct {
		Id   uint
		Name string
	}
	InternetLayer struct {
		Id   uint
		Name string
	}
)
