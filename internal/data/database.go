package data

import (
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"time"
)

type DatabaseAdminFeatures interface {
	UpdatePasswordAndSetExpiration(username, newPassword string, duration time.Duration) (bool, error)
	GetUserInterfacePermissions(username string) (succeed bool, user *objects.User, captureInterfaces map[string]struct{}, arpScanInterfaces map[string]struct{}, arpSpoofInterfaces map[string]struct{}, err error)
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
