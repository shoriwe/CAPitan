package memory

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"golang.org/x/crypto/bcrypt"
	"sync"
	"time"
)

type Memory struct {
	usersMutex                        *sync.Mutex
	users                             map[string]*objects.User
	captureInterfacePermissionsMutex  *sync.Mutex
	captureInterfacePermissions       map[uint]*objects.CapturePermission
	arpScanInterfacePermissionsMutex  *sync.Mutex
	arpScanInterfacePermissions       map[uint]*objects.ARPScanPermission
	arpSpoofInterfacePermissionsMutex *sync.Mutex
	arpSpoofInterfacePermissions      map[uint]*objects.ARPSpoofPermission
	captureSessions                   map[uint]*objects.CaptureSession
	captureSessionsMutex              *sync.Mutex
	nextUserId                        uint
	nextCapturePermissionId           uint
	nextARPScanPermissionId           uint
	nextARPSpoofPermissionId          uint
}

func (memory *Memory) ListUserCaptures(username string) (bool, []*objects.CaptureSession, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil, nil
	}
	memory.captureSessionsMutex.Lock()
	defer memory.captureSessionsMutex.Unlock()
	var result []*objects.CaptureSession
	for _, captureSession := range memory.captureSessions {
		if captureSession.UserId == user.Id {
			result = append(result, captureSession)
		}
	}
	return true, result, nil
}

func (memory *Memory) DeleteCaptureInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.captureInterfacePermissionsMutex.Lock()
	defer memory.captureInterfacePermissionsMutex.Unlock()
	for id, capturePermission := range memory.captureInterfacePermissions {
		if capturePermission.UsersId == user.Id && capturePermission.Interface == i {
			delete(memory.captureInterfacePermissions, id)
			return true, nil
		}
	}
	return false, nil
}

func (memory *Memory) DeleteARPScanInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.arpScanInterfacePermissionsMutex.Lock()
	defer memory.arpScanInterfacePermissionsMutex.Unlock()
	for id, arpScanPermission := range memory.arpScanInterfacePermissions {
		if arpScanPermission.UsersId == user.Id && arpScanPermission.Interface == i {
			delete(memory.arpScanInterfacePermissions, id)
			return true, nil
		}
	}
	return false, nil
}

func (memory *Memory) DeleteARPSpoofInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.arpSpoofInterfacePermissionsMutex.Lock()
	defer memory.arpSpoofInterfacePermissionsMutex.Unlock()
	for id, arpSpoofPermission := range memory.arpSpoofInterfacePermissions {
		if arpSpoofPermission.UsersId == user.Id && arpSpoofPermission.Interface == i {
			delete(memory.arpSpoofInterfacePermissions, id)
			return true, nil
		}
	}
	return false, nil
}

func (memory *Memory) AddCaptureInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.captureInterfacePermissionsMutex.Lock()
	defer memory.captureInterfacePermissionsMutex.Unlock()
	for _, capturePermission := range memory.captureInterfacePermissions {
		if capturePermission.UsersId == user.Id && capturePermission.Interface == i {
			return false, nil
		}
	}
	memory.captureInterfacePermissions[memory.nextCapturePermissionId] = &objects.CapturePermission{
		Id:        memory.nextCapturePermissionId,
		UsersId:   user.Id,
		Interface: i,
	}
	memory.nextCapturePermissionId++
	return false, nil
}

func (memory *Memory) AddARPScanInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.arpScanInterfacePermissionsMutex.Lock()
	defer memory.arpScanInterfacePermissionsMutex.Unlock()
	for _, arpScanPermission := range memory.arpScanInterfacePermissions {
		if arpScanPermission.UsersId == user.Id && arpScanPermission.Interface == i {
			return false, nil
		}
	}
	memory.arpScanInterfacePermissions[memory.nextARPScanPermissionId] = &objects.ARPScanPermission{
		Id:        memory.nextARPScanPermissionId,
		UsersId:   user.Id,
		Interface: i,
	}
	memory.nextARPScanPermissionId++
	return false, nil
}

func (memory *Memory) AddARPSpoofInterfacePrivilege(username string, i string) (bool, error) {
	memory.usersMutex.Lock()
	user, found := memory.users[username]
	memory.usersMutex.Unlock()
	if !found {
		return false, nil
	}
	memory.arpSpoofInterfacePermissionsMutex.Lock()
	defer memory.arpSpoofInterfacePermissionsMutex.Unlock()
	for _, arpSpoofPermission := range memory.arpSpoofInterfacePermissions {
		if arpSpoofPermission.UsersId == user.Id && arpSpoofPermission.Interface == i {
			return false, nil
		}
	}
	memory.arpSpoofInterfacePermissions[memory.nextARPSpoofPermissionId] = &objects.ARPSpoofPermission{
		Id:        memory.nextARPSpoofPermissionId,
		UsersId:   user.Id,
		Interface: i,
	}
	memory.nextARPSpoofPermissionId++
	return false, nil
}

func (memory *Memory) UpdateUserStatus(username string, isAdmin, isEnabled bool) (succeed bool, updateError error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	_, found := memory.users[username]
	if !found {
		return false, nil
	}
	memory.users[username].IsAdmin = isAdmin
	memory.users[username].IsEnabled = isEnabled
	return true, nil
}

func (memory *Memory) GetUserInterfacePermissions(username string) (succeed bool, user *objects.User, captureInterfaces map[string]struct{}, arpScanInterfaces map[string]struct{}, arpSpoofInterfaces map[string]struct{}, err error) {
	memory.usersMutex.Lock()
	user, succeed = memory.users[username]
	memory.usersMutex.Unlock()
	if !succeed {
		return false, nil, nil, nil, nil, nil
	}

	captureInterfaces = map[string]struct{}{}
	arpScanInterfaces = map[string]struct{}{}
	arpSpoofInterfaces = map[string]struct{}{}

	// Capture
	memory.captureInterfacePermissionsMutex.Lock()
	for _, permission := range memory.captureInterfacePermissions {
		captureInterfaces[permission.Interface] = struct{}{}
	}
	memory.captureInterfacePermissionsMutex.Unlock()

	// ARP Scan
	memory.arpScanInterfacePermissionsMutex.Lock()
	for _, permission := range memory.arpScanInterfacePermissions {
		arpScanInterfaces[permission.Interface] = struct{}{}
	}
	memory.arpScanInterfacePermissionsMutex.Unlock()

	// ARP Spoof
	memory.arpSpoofInterfacePermissionsMutex.Lock()
	for _, permission := range memory.arpSpoofInterfacePermissions {
		arpSpoofInterfaces[permission.Interface] = struct{}{}
	}
	memory.arpSpoofInterfacePermissionsMutex.Unlock()

	return true, user, captureInterfaces, arpScanInterfaces, arpSpoofInterfaces, nil
}

func (memory *Memory) CreateUser(username string) (bool, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	_, found := memory.users[username]
	if found {
		return false, nil
	}
	var (
		rawPassword         []byte
		rawSecurityQuestion []byte
		rawAnswer           []byte
	)
	_, readError := rand.Read(rawPassword)
	if readError != nil {
		return false, readError
	}
	_, readError = rand.Read(rawSecurityQuestion)
	if readError != nil {
		return false, readError
	}
	_, readError = rand.Read(rawAnswer)
	if readError != nil {
		return false, readError
	}
	passwordHash, hashingError := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(rawPassword)), bcrypt.DefaultCost)
	if hashingError != nil {
		return false, hashingError
	}
	memory.users[username] = &objects.User{
		Id:                     memory.nextUserId,
		Username:               username,
		PasswordHash:           string(passwordHash),
		SecurityQuestion:       hex.EncodeToString(rawSecurityQuestion),
		SecurityQuestionAnswer: hex.EncodeToString(rawSecurityQuestion),
		IsAdmin:                false,
		IsEnabled:              false,
		PasswordExpirationDate: time.Time{},
	}
	memory.nextUserId++
	return true, nil
}

func (memory *Memory) GetUserByUsername(username string) (bool, *objects.User, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	result, found := memory.users[username]
	return found, result, nil
}

func (memory *Memory) UpdatePasswordAndSetExpiration(username, newPassword string, duration time.Duration) (bool, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	_, found := memory.users[username]
	if !found {
		return false, nil
	}
	newPasswordHash, generationError := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if generationError != nil {
		return false, generationError
	}
	memory.users[username].PasswordHash = string(newPasswordHash)
	memory.users[username].PasswordExpirationDate = time.Now().Add(duration)
	return true, nil
}

func (memory *Memory) UpdatePassword(username, oldPassword, newPassword string) (bool, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	user, found := memory.users[username]
	if !found {
		return false, nil
	}
	compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if compareError != nil {
		if compareError == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, compareError
	}
	newPasswordHash, generateError := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if generateError != nil {
		return false, generateError
	}
	memory.users[username].PasswordHash = string(newPasswordHash)
	memory.users[username].PasswordExpirationDate = time.Time{}
	return true, nil
}

func (memory *Memory) UpdateSecurityQuestion(username, password, newQuestion, newQuestionAnswer string) (bool, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	user, found := memory.users[username]
	if !found {
		return false, nil
	}
	compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if compareError != nil {
		if compareError == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, compareError
	}
	newQuestionAnswerHash, generateError := bcrypt.GenerateFromPassword([]byte(newQuestionAnswer), bcrypt.DefaultCost)
	if generateError != nil {
		return false, generateError
	}
	memory.users[username].SecurityQuestion = newQuestion
	memory.users[username].SecurityQuestionAnswer = string(newQuestionAnswerHash)
	return true, nil
}

func (memory *Memory) ListUsers(username string) ([]*objects.User, error) {
	memory.usersMutex.Lock()
	defer memory.usersMutex.Unlock()
	var result []*objects.User
	for _, user := range memory.users {
		if user.Username != username {
			result = append(result, user)
		}
	}
	return result, nil
}

func NewInMemoryDB() data.Database {
	result := &Memory{
		usersMutex:                        new(sync.Mutex),
		captureInterfacePermissionsMutex:  new(sync.Mutex),
		arpScanInterfacePermissionsMutex:  new(sync.Mutex),
		arpSpoofInterfacePermissionsMutex: new(sync.Mutex),
		captureSessionsMutex:              new(sync.Mutex),
		users:                             map[string]*objects.User{},
		captureInterfacePermissions:       map[uint]*objects.CapturePermission{},
		arpScanInterfacePermissions:       map[uint]*objects.ARPScanPermission{},
		arpSpoofInterfacePermissions:      map[uint]*objects.ARPSpoofPermission{},
		captureSessions:                   map[uint]*objects.CaptureSession{},
		nextUserId:                        2,
		nextCapturePermissionId:           1,
		nextARPScanPermissionId:           1,
		nextARPSpoofPermissionId:          1,
	}
	result.users["admin"] = &objects.User{
		Id:                     1,
		Username:               "admin",
		PasswordHash:           "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		SecurityQuestion:       "Respond this with \"admin\"",
		SecurityQuestionAnswer: "$2a$10$ouA9iRdw/T1sSGnJiAwt4.qBH8Hs7kw0ieby8IhNDHRxPfNN7/VkW", // admin
		IsAdmin:                true,
		IsEnabled:              true,
		PasswordExpirationDate: time.Now().Add(30 * time.Minute),
	}
	return result
}
