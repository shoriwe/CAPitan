package noauth

import (
	"github.com/google/gopacket"
	arp_scanner "github.com/shoriwe/CAPitan/internal/arp-scanner"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"time"
)

var admin = &objects.User{
	Id:                     1,
	Username:               "admin",
	PasswordHash:           "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
	SecurityQuestion:       "Respond this with \"admin\"",
	SecurityQuestionAnswer: "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
	IsAdmin:                true,
	IsEnabled:              true,
	PasswordExpirationDate: time.Now().Add(30 * time.Minute),
}

type NoAuth struct {
}

func (noAuth *NoAuth) SaveARPScan(username string, scanName string, interfaceName string, script string, hosts map[string]arp_scanner.Host, start time.Time, finish time.Time) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (noAuth *NoAuth) ListUserARPScans(username string) (bool, []*objects.ARPScanSession, error) {
	var scans []*objects.ARPScanSession
	scans = append(scans,
		&objects.ARPScanSession{
			Id:        1,
			Interface: "eth0",
			UserId:    1,
			Name:      "Test 1",
			Started:   time.Now(),
			Ended:     time.Now().Add(time.Second),
			Script:    nil,
		})
	scans = append(scans,
		&objects.ARPScanSession{
			Id:        2,
			Interface: "eth1",
			UserId:    1,
			Name:      "Test",
			Started:   time.Now(),
			Ended:     time.Now().Add(time.Second),
			Script:    nil,
		})
	scans = append(scans,
		&objects.ARPScanSession{
			Id:        3,
			Interface: "lo",
			UserId:    1,
			Name:      "Test 2",
			Started:   time.Now(),
			Ended:     time.Now().Add(time.Second),
			Script:    nil,
		})

	return true, scans, nil
}

func (noAuth *NoAuth) SaveImportCapture(username string, name string, description string, script string, topologyOptions interface{}, hostCountOptions interface{}, layer4Options interface{}, streamTypeCountOptions interface{}, packets []gopacket.Packet, streams []capture.Data, pcap []byte) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) QueryCapture(username, captureName string) (succeed bool, captureSession *objects.CaptureSession, packets []map[string]interface{}, streams []capture.Data, queryError error) {
	panic("implement me")
}

func (noAuth *NoAuth) SaveInterfaceCapture(username, captureName, interfaceName, description, script string, promiscuous bool, topology, hostPacketCount, layer4Count, streamTypeCount interface{}, packets []gopacket.Packet, streams []capture.Data, pcapContents []byte, start, finish time.Time) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) CheckIfUserCaptureNameWasAlreadyTaken(username string, name string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) ListUserCaptures(username string) (bool, []*objects.CaptureSession, error) {
	return true, []*objects.CaptureSession{
		&objects.CaptureSession{
			Id:           1,
			UserId:       1,
			Interface:    "lo",
			Name:         "Debug Application",
			Description:  "Debugging CAPitan",
			Started:      time.Now(),
			Ended:        time.Now().Add(24 * time.Hour),
			Pcap:         nil,
			FilterScript: nil,
		},
		&objects.CaptureSession{
			Id:           2,
			UserId:       1,
			Interface:    "eth0",
			Name:         "Monitoring office",
			Description:  "Monitoring suspicious traffic in the office network",
			Started:      time.Now(),
			Ended:        time.Now().Add(24 * time.Hour),
			Pcap:         nil,
			FilterScript: nil,
		},
		&objects.CaptureSession{
			Id:           3,
			UserId:       1,
			Interface:    "tun0",
			Name:         "Test VPN",
			Description:  "Testing the VPN of to house",
			Started:      time.Now(),
			Ended:        time.Now().Add(24 * time.Hour),
			Pcap:         nil,
			FilterScript: nil,
		},
	}, nil
}

func (noAuth *NoAuth) DeleteCaptureInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) DeleteARPScanInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) DeleteARPSpoofInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) AddCaptureInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) AddARPScanInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) AddARPSpoofInterfacePrivilege(username string, i string) (bool, error) {
	panic("implement me")
}

func (noAuth *NoAuth) UpdateUserStatus(username string, isAdmin, isEnabled bool) (succeed bool, updateError error) {
	return true, nil
}

func (noAuth *NoAuth) GetUserInterfacePermissions(username string) (succeed bool, user *objects.User, captureInterfaces map[string]*objects.CapturePermission, arpScanInterfaces map[string]*objects.ARPScanPermission, arpSpoofInterfaces map[string]*objects.ARPSpoofPermission, err error) {
	user = &objects.User{
		Id:                     1,
		Username:               "admin",
		PasswordHash:           "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		SecurityQuestion:       "Respond this with \"admin\"",
		SecurityQuestionAnswer: "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		IsAdmin:                false,
		IsEnabled:              true,
		PasswordExpirationDate: time.Now().Add(30 * time.Minute),
	}
	captureInterfaces = map[string]*objects.CapturePermission{"eth0": {
		Id:        1,
		UsersId:   1,
		Interface: "eth0",
	}}
	arpScanInterfaces = map[string]*objects.ARPScanPermission{"eth0": {
		Id:        1,
		UsersId:   1,
		Interface: "eth0",
	}, "eth1": {
		Id:        2,
		UsersId:   1,
		Interface: "eth1",
	}}
	arpSpoofInterfaces = map[string]*objects.ARPSpoofPermission{"eth2": {
		Id:        1,
		UsersId:   1,
		Interface: "eth2",
	}}
	return true, user, captureInterfaces, arpScanInterfaces, arpSpoofInterfaces, nil
}

func (noAuth *NoAuth) CreateUser(username string) (bool, error) {
	return true, nil
}

func (noAuth *NoAuth) ListUsers(username string) ([]*objects.User, error) {
	return []*objects.User{
		&objects.User{
			Username: "john",
			IsAdmin:  true,
		},
		&objects.User{
			Username:  "sulcud",
			IsEnabled: true,
		},
	}, nil
}

func (noAuth *NoAuth) GetUserByUsername(_ string) (bool, *objects.User, error) {
	return true, admin, nil
}

func (noAuth *NoAuth) UpdatePasswordAndSetExpiration(_, _ string, _ time.Duration) (bool, error) {
	return true, nil
}

func (noAuth *NoAuth) UpdatePassword(_, _, _ string) (bool, error) {
	return true, nil
}

func (noAuth *NoAuth) UpdateSecurityQuestion(_, _, _, _ string) (bool, error) {
	return true, nil
}

func NewNoAuthDB() data.Database {
	return &NoAuth{}
}
