package middleware

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"github.com/google/gopacket/pcap"
	"github.com/shoriwe/CAPitan/internal/data"
	"github.com/shoriwe/CAPitan/internal/data/objects"
	"github.com/shoriwe/CAPitan/internal/limit"
	"github.com/shoriwe/CAPitan/internal/logs"
	"github.com/shoriwe/CAPitan/internal/sessions"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type (
	Context struct {
		StatusCode     int
		Redirect       string
		Headers        map[string]string
		Body           string
		NavigationBar  string
		User           *objects.User
		SessionCookie  *http.Cookie
		WriteBody      bool
		ResponseWriter http.ResponseWriter
		Request        *http.Request
		NewCookie      *http.Cookie
	}
	HandleFunc func(middleware *Middleware, context *Context) bool
	Middleware struct {
		data.Database
		*logs.Logger
		*limit.Limiter
		devices               map[string]pcap.Interface
		reservedCaptures      map[string]map[string]struct{}
		reservedCapturesMutex *sync.Mutex
		Templates             embed.FS
		LoginSessions         *sessions.Sessions
		ResetSessions         *sessions.Sessions
	}
)

var (
	validUsername         = regexp.MustCompile("\\w+")
	validPassword         = regexp.MustCompile(".+")
	validSecurityQuestion = regexp.MustCompile(".+")
	validAnswer           = regexp.MustCompile(".+")
)

func NewContext(responseWriter http.ResponseWriter, request *http.Request) *Context {
	return &Context{
		StatusCode:     http.StatusOK,
		Redirect:       "",
		Headers:        map[string]string{},
		Body:           "",
		NavigationBar:  "",
		User:           nil,
		SessionCookie:  nil,
		WriteBody:      true,
		ResponseWriter: responseWriter,
		Request:        request,
		NewCookie:      nil,
	}
}

func New(c data.Database, l *logs.Logger, t embed.FS) *Middleware {
	return &Middleware{
		Database:              c,
		Logger:                l,
		Templates:             t,
		reservedCaptures:      map[string]map[string]struct{}{},
		reservedCapturesMutex: new(sync.Mutex),
		Limiter:               limit.NewLimiter(),
		LoginSessions:         sessions.NewSessions(),
		ResetSessions:         sessions.NewSessions(),
		devices:               nil,
	}
}

func (middleware *Middleware) Handle(handlerFunctions ...HandleFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		context := NewContext(responseWriter, request)
		for _, handlerFunction := range handlerFunctions {
			if !handlerFunction(middleware, context) {
				break
			}
		}
		if !context.WriteBody {
			return
		}
		for key, value := range context.Headers {
			responseWriter.Header().Set(key, value)
		}
		if context.NewCookie != nil {
			context.NewCookie.Path = symbols.Root
			http.SetCookie(responseWriter, context.NewCookie)
		}
		if context.Redirect != "" {
			http.Redirect(responseWriter, request, context.Redirect, http.StatusFound)
			return
		}
		responseWriter.WriteHeader(context.StatusCode)
		_, writeError := responseWriter.Write([]byte(context.Body))
		if writeError != nil {
			go middleware.LogError(request, writeError)
		}
	}
}

func (middleware *Middleware) Login(request *http.Request, username, password string) (*objects.User, bool) {
	found, user, err := middleware.Database.GetUserByUsername(username)
	if err != nil { // Check if the user at least exists
		go middleware.LogError(request, err)
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !found {
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !user.IsEnabled {
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !user.PasswordExpirationDate.Equal(time.Time{}) {
		if time.Now().After(user.PasswordExpirationDate) {
			go middleware.LogLoginAttempt(request, username, false)
			return nil, false
		}
	}
	if compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); compareError != nil {
		if compareError != bcrypt.ErrMismatchedHashAndPassword {
			go middleware.LogError(request, compareError)
		}
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	go middleware.LogLoginAttempt(request, username, true)
	return user, true
}

func (middleware *Middleware) LoginWithSecurityQuestion(request *http.Request, username, answer string) (*objects.User, bool) {
	found, user, err := middleware.Database.GetUserByUsername(username)
	if err != nil { // Check if the user at least exists
		go middleware.LogError(request, err)
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !found {
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !user.IsEnabled {
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	if !user.PasswordExpirationDate.Equal(time.Time{}) {
		if time.Now().After(user.PasswordExpirationDate) {
			go middleware.LogLoginAttempt(request, username, false)
			return nil, false
		}
	}
	if compareError := bcrypt.CompareHashAndPassword([]byte(user.SecurityQuestionAnswer), []byte(answer)); compareError != nil {
		if compareError != bcrypt.ErrMismatchedHashAndPassword {
			go middleware.LogError(request, compareError)
		}
		go middleware.LogLoginAttempt(request, username, false)
		return nil, false
	}
	go middleware.LogLoginAttempt(request, username, true)
	return user, true
}

func (middleware *Middleware) GenerateCookieFor(request *http.Request, username string, duration time.Duration) (string, bool) {
	cookie, sessionCreationError := middleware.LoginSessions.CreateSession(username, duration)
	if sessionCreationError != nil {
		go middleware.LogError(request, sessionCreationError)
		return "", false
	}
	go middleware.LogCookieGeneration(request, username)
	return cookie, true
}

func (middleware *Middleware) ResetPassword(request *http.Request, username string, duration time.Duration) (string, bool) {
	rawNewPassword := make([]byte, 12)
	_, readError := rand.Read(rawNewPassword)
	if readError != nil {
		go middleware.LogError(request, readError)
		go middleware.LogSystemUpdatePassword(request, username, false)
		return "", false
	}
	newPassword := hex.EncodeToString(rawNewPassword)
	succeed, err := middleware.UpdatePasswordAndSetExpiration(username, newPassword, duration)
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogSystemUpdatePassword(request, username, succeed)
	return newPassword, succeed
}

func (middleware *Middleware) UpdatePassword(request *http.Request, username, oldPassword, newPassword, confirmation string) bool {
	if newPassword != confirmation {
		go middleware.LogUpdatePassword(request, username, false)
		return false
	}
	if !validPassword.MatchString(newPassword) {
		return false
	}
	succeed, err := middleware.Database.UpdatePassword(username, oldPassword, newPassword)
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogUpdatePassword(request, username, succeed)
	return succeed
}

func (middleware *Middleware) UpdateSecurityQuestion(request *http.Request, username, password, newQuestion, newQuestionAnswer string) bool {
	if !validSecurityQuestion.MatchString(newQuestion) {
		return false
	}
	if !validAnswer.MatchString(newQuestionAnswer) {
		return false
	}
	succeed, err := middleware.Database.UpdateSecurityQuestion(username, password, newQuestion, newQuestionAnswer)
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogUpdateSecurityQuestion(request, username, succeed)
	return succeed
}

func (middleware *Middleware) Limit(request *http.Request) bool {
	rawHostURIHash := sha3.New512()
	rawHostURIHash.Write([]byte(request.RequestURI))
	ip, _, _ := net.SplitHostPort(request.Host)
	rawHostURIHash.Write([]byte(ip))
	hostURIHash := hex.EncodeToString(rawHostURIHash.Sum(nil))
	if middleware.LimitAndCheck(hostURIHash, 30*time.Minute) {
		return true
	}
	go middleware.LogBannedByLimit(request)
	return false
}

func (middleware *Middleware) AdminListUsers(request *http.Request, username string) ([]*objects.User, bool) {
	users, err := middleware.Database.ListUsers(username)
	if err != nil {
		go middleware.LogError(request, err)
		return nil, false
	}
	return users, true
}

func (middleware *Middleware) AdminCreateUser(request *http.Request, username string) bool {
	if !validUsername.MatchString(username) {
		return false
	}
	succeed, userCreationError := middleware.Database.CreateUser(username)
	if userCreationError != nil {
		go middleware.LogError(request, userCreationError)
	}
	go middleware.LogUserCreation(request, succeed, username)
	return succeed
}

func (middleware *Middleware) AdminUpdatePassword(request *http.Request, username, password string) bool {
	if !validPassword.MatchString(password) {
		return false
	}
	succeed, updateError := middleware.Database.UpdatePasswordAndSetExpiration(username, password, symbols.LoginSessionDuration)
	if updateError != nil {
		go middleware.LogError(request, updateError)
	}
	go middleware.LogAdminUpdatePassword(request, username, succeed)
	return succeed
}

func (middleware *Middleware) AdminUpdateStatus(request *http.Request, username string, isAdmin, isEnabled bool) bool {
	succeed, updateError := middleware.Database.UpdateUserStatus(username, isAdmin, isEnabled)
	if updateError != nil {
		go middleware.LogError(request, updateError)
	}
	go middleware.LogAdminUpdateUserStatus(request, username, isAdmin, isEnabled, succeed)
	return succeed
}

func (middleware *Middleware) ListNetInterfaces(request *http.Request) map[string]pcap.Interface {
	if middleware.devices == nil {
		devices, findInterfacesError := pcap.FindAllDevs()
		if findInterfacesError != nil {
			go middleware.LogError(request, findInterfacesError)
		}
		middleware.devices = map[string]pcap.Interface{}
		for _, device := range devices {
			middleware.devices[device.Name] = device
		}
	}
	return middleware.devices
}

func (middleware *Middleware) QueryUserPermissions(request *http.Request, username string) (user *objects.User, captureInterfaces map[string]*objects.CapturePermission, arpScanInterfaces map[string]*objects.ARPScanPermission, arpSpoofInterfaces map[string]*objects.ARPSpoofPermission, succeed bool) {
	var getError error
	succeed, user, captureInterfaces, arpScanInterfaces, arpSpoofInterfaces, getError = middleware.Database.GetUserInterfacePermissions(username)
	if getError != nil {
		go middleware.LogError(request, getError)
		go middleware.LogQueryUserPermissions(request, username, false)
		return nil, nil, nil, nil, false
	}
	go middleware.LogQueryUserPermissions(request, username, succeed)
	return user, captureInterfaces, arpScanInterfaces, arpSpoofInterfaces, succeed
}

func (middleware *Middleware) AdminDeleteARPSpoofInterfacePrivilege(request *http.Request, username string, i string) bool {
	succeed, grantError := middleware.Database.DeleteARPSpoofInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminDeleteARPSpoofPrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) AdminAddARPSpoofInterfacePrivilege(request *http.Request, username string, i string) bool {
	interfaces := middleware.ListNetInterfaces(request)
	if interfaces == nil {
		go middleware.LogAdminAddARPSpoofPrivilege(request, username, i, false)
		return false
	}
	if _, found := interfaces[i]; !found {
		go middleware.LogAdminAddARPSpoofPrivilege(request, username, i, false)
		return false
	}
	succeed, grantError := middleware.Database.AddARPSpoofInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminAddARPSpoofPrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) AdminDeleteARPScanInterfacePrivilege(request *http.Request, username string, i string) bool {
	succeed, grantError := middleware.Database.DeleteARPScanInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminDeleteARPScanPrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) AdminAddARPScanInterfacePrivilege(request *http.Request, username string, i string) bool {
	interfaces := middleware.ListNetInterfaces(request)
	if interfaces == nil {
		go middleware.LogAdminAddARPScanPrivilege(request, username, i, false)
		return false
	}
	if _, found := interfaces[i]; !found {
		go middleware.LogAdminAddARPScanPrivilege(request, username, i, false)
		return false
	}
	succeed, grantError := middleware.Database.AddARPScanInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminAddARPScanPrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) AdminDeleteCaptureInterfacePrivilege(request *http.Request, username string, i string) bool {
	succeed, grantError := middleware.Database.DeleteCaptureInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminDeleteCapturePrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) AdminAddCaptureInterfacePrivilege(request *http.Request, username string, i string) bool {
	interfaces := middleware.ListNetInterfaces(request)
	if interfaces == nil {
		go middleware.LogAdminAddCapturePrivilege(request, username, i, false)
		return false
	}
	if _, found := interfaces[i]; !found {
		go middleware.LogAdminAddCapturePrivilege(request, username, i, false)
		return false
	}
	succeed, grantError := middleware.Database.AddCaptureInterfacePrivilege(username, i)
	if grantError != nil {
		go middleware.LogError(request, grantError)
	}
	go middleware.LogAdminAddCapturePrivilege(request, username, i, succeed)
	return succeed
}

func (middleware *Middleware) ListUserCaptures(request *http.Request, username string) (bool, []*objects.CaptureSession) {
	succeed, captures, listError := middleware.Database.ListUserCaptures(username)
	if listError != nil {
		go middleware.LogError(request, listError)
		go middleware.LogListUserCaptures(request, username, false)
		return false, nil
	}
	go middleware.LogListUserCaptures(request, username, succeed)
	return succeed, captures
}

func (middleware *Middleware) isCapturenameAlreadyTaken(username, captureName string) bool {
	middleware.reservedCapturesMutex.Lock()
	defer middleware.reservedCapturesMutex.Unlock()
	user, found := middleware.reservedCaptures[username]
	if found {
		_, found = user[captureName]
		return found
	}
	return false
}

func (middleware *Middleware) UserCaptureNameAlreadyTaken(request *http.Request, username, captureName string) bool {
	if middleware.isCapturenameAlreadyTaken(username, captureName) {
		return true
	}
	succeed, checkError := middleware.Database.CheckIfUserCaptureNameWasAlreadyTaken(username, captureName)
	if checkError != nil {
		go middleware.LogError(request, checkError)
		return false
	}
	return succeed
}

func (middleware *Middleware) ReserveUserCaptureName(request *http.Request, username, captureName string) bool {
	if middleware.isCapturenameAlreadyTaken(username, captureName) {
		go middleware.LogReserveCaptureNameForUser(request, username, captureName, false)
		return false
	}
	middleware.reservedCapturesMutex.Lock()
	defer middleware.reservedCapturesMutex.Unlock()
	_, found := middleware.reservedCaptures[username]
	if !found {
		go middleware.LogReserveCaptureNameForUser(request, username, captureName, true)
		middleware.reservedCaptures[username] = map[string]struct{}{captureName: {}}
		return true
	}
	go middleware.LogReserveCaptureNameForUser(request, username, captureName, true)
	middleware.reservedCaptures[username][captureName] = struct{}{}
	return true
}

func (middleware *Middleware) RemoveReservedCaptureName(request *http.Request, username, captureName string) bool {
	if middleware.isCapturenameAlreadyTaken(username, captureName) {
		middleware.reservedCapturesMutex.Lock()
		defer middleware.reservedCapturesMutex.Unlock()
		delete(middleware.reservedCaptures[username], captureName)
		go middleware.LogRemoveReserveCaptureNameForUser(request, username, captureName, true)
		return true
	}
	go middleware.LogRemoveReserveCaptureNameForUser(request, username, captureName, false)
	return false
}
