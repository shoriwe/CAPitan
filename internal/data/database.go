package data

import (
	"github.com/google/gopacket"
	"github.com/shoriwe/CAPitan/internal/capture"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"time"
)

type DatabaseAdminFeatures interface {
	UpdatePasswordAndSetExpiration(username, newPassword string, duration time.Duration) (bool, error)
	GetUserInterfacePermissions(username string) (succeed bool, user *objects.User, captureInterfaces map[string]*objects.CapturePermission, arpScanInterfaces map[string]*objects.ARPScanPermission, arpSpoofInterfaces map[string]*objects.ARPSpoofPermission, err error)
	ListUsers(username string) ([]*objects.User, error)
	CreateUser(username string) (bool, error)
	GetUserByUsername(username string) (bool, *objects.User, error)
	UpdateUserStatus(username string, isAdmin, isEnabled bool) (succeed bool, updateError error)
	DeleteCaptureInterfacePrivilege(username, i string) (bool, error)
	DeleteARPScanInterfacePrivilege(username, i string) (bool, error)
	DeleteARPSpoofInterfacePrivilege(username, i string) (bool, error)
	AddCaptureInterfacePrivilege(username, i string) (bool, error)
	AddARPScanInterfacePrivilege(username, i string) (bool, error)
	AddARPSpoofInterfacePrivilege(username, i string) (bool, error)
}

type DatabaseUserFeatures interface {
	ListUserCaptures(username string) (bool, []*objects.CaptureSession, error)
	CheckIfUserCaptureNameWasAlreadyTaken(username string, name string) (bool, error)
	SaveInterfaceCapture(username, captureName, interfaceName, description, script string, promiscuous bool, topologyOptions, hostPacketCountOptions, layer4CountOptions, streamTypeCountOptions interface{}, packets []gopacket.Packet, streams []capture.Data, pcapContents []byte, start, finish time.Time) (bool, error)
	QueryCapture(username, captureName string) (succeed bool, captureSession *objects.CaptureSession, packets []map[string]interface{}, streams []capture.Data, queryError error)
	SaveImportCapture(username string, name string, description string, script string, topologyOptions interface{}, hostCountOptions interface{}, layer4Options interface{}, streamTypeCountOptions interface{}, packets []gopacket.Packet, streams []capture.Data, pcap []byte) (bool, error)
}

type DatabaseGlobalFeatures interface {
	UpdatePassword(username, oldPassword, newPassword string) (bool, error)
	UpdateSecurityQuestion(username, password, newQuestion, newQuestionAnswer string) (bool, error)
}

type Database interface {
	DatabaseAdminFeatures
	DatabaseUserFeatures
	DatabaseGlobalFeatures
}
