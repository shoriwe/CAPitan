package objects

import "time"

type (
	InterfaceInformation struct {
		Name    string
		Address string
	}
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
	ARPScanSession struct {
		Id        uint
		Interface string
		UserId    uint
		Name      string
		Started   time.Time
		Ended     time.Time
		Script    []byte
		Hosts     []byte
	}
	ARPScanSessionAdminView struct {
		User    *User
		Session *ARPScanSession
	}
	CaptureSession struct {
		Id                  uint
		UserId              uint
		Interface           string
		Promiscuous         bool
		Name                string
		Description         string
		Started             time.Time
		Ended               time.Time
		Pcap                []byte
		FilterScript        []byte
		TopologyJson        []byte
		HostCountJson       []byte
		LayerCountJson      []byte
		StreamTypeCountJson []byte
	}
	CaptureSessionAdminView struct {
		User    *User
		Session *CaptureSession
	}
	TCPStreamType struct {
		Id         uint
		StreamType string
	}
	TCPStream struct {
		Id               uint
		CaptureSessionId uint
		TCPStreamType    string
		Contents         []byte
	}
	Packet struct {
		Id                 uint
		CaptureSessionsId  uint
		TransportLayer     string
		InternetLayer      string
		ApplicationLayer   string
		SourceAddress      string
		SourcePort         uint
		DestinationAddress string
		DestinationPort    uint
		Contents           []byte
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
