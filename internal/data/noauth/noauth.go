package noauth

import (
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

func (noAuth *NoAuth) GetUserInterfacePermissions(username string) (succeed bool, user *objects.User, captureInterfaces map[string]struct{}, arpScanInterfaces map[string]struct{}, arpSpoofInterfaces map[string]struct{}, err error) {
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
	captureInterfaces = map[string]struct{}{"eth0": {}}
	arpScanInterfaces = map[string]struct{}{"eth0": {}, "eth1": {}}
	arpSpoofInterfaces = map[string]struct{}{"eth2": {}}
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
