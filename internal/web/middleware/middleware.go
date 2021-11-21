package middleware

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
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
		Templates     embed.FS
		LoginSessions *sessions.Sessions
		ResetSessions *sessions.Sessions
	}
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
		Database:      c,
		Logger:        l,
		Templates:     t,
		Limiter:       limit.NewLimiter(),
		LoginSessions: sessions.NewSessions(),
		ResetSessions: sessions.NewSessions(),
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
	user, err := middleware.Database.GetUserByUsername(username)
	if err != nil { // Check if the user at least exists
		go middleware.LogError(request, err)
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
	user, err := middleware.Database.GetUserByUsername(username)
	if err != nil { // Check if the user at least exists
		go middleware.LogError(request, err)
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
	succeed, err := middleware.Database.UpdatePassword(username, oldPassword, newPassword)
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogUpdatePassword(request, username, succeed)
	return succeed
}

func (middleware *Middleware) UpdateSecurityQuestion(request *http.Request, username, password, newQuestion, newQuestionAnswer string) bool {
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

func (middleware *Middleware) AdminCreateUser(request *http.Request, username string) {
	succeed, userCreationError := middleware.Database.CreateUser(username)
	if userCreationError != nil {
		go middleware.LogError(request, userCreationError)
	}
	go middleware.LogUserCreation(request, succeed, username)
}
