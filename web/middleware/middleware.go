package middleware

import (
	"embed"
	"encoding/hex"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"github.com/shoriwe/CAPitan/limit"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/sessions"
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
		User           *objects.User
		WriteBody      bool
		ResponseWriter http.ResponseWriter
		Request        *http.Request
	}
	HandleFunc func(middleware *Middleware, context *Context) bool
	Middleware struct {
		// dataController   data.Database
		// logger *logs.Logger
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
		User:           nil,
		WriteBody:      true,
		ResponseWriter: responseWriter,
		Request:        request,
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
	succeed := true
	if user == nil || err != nil { // Check if the user at least exists
		succeed = false
	} else if time.Now().After(user.PasswordExpirationDate) || !user.IsEnabled { // Check if is still available
		succeed = false
		user = nil
	} else if compareError := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); compareError != nil {
		succeed = false
		user = nil
		if compareError != bcrypt.ErrMismatchedHashAndPassword {
			err = compareError
		}
	}
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogLoginAttempt(request, username, succeed)
	return user, succeed
}

func (middleware *Middleware) LoginWithSecurityQuestion(request *http.Request, username, answer string) (*objects.User, bool) {
	user, err := middleware.Database.GetUserByUsername(username)
	succeed := true
	if user == nil || err != nil { // Check if the user at least exists
		succeed = false
	} else if time.Now().After(user.PasswordExpirationDate) || !user.IsEnabled { // Check if is still available
		succeed = false
		user = nil
	} else if compareError := bcrypt.CompareHashAndPassword([]byte(user.SecurityQuestionAnswer), []byte(answer)); compareError != nil {
		succeed = false
		user = nil
		if compareError != bcrypt.ErrMismatchedHashAndPassword {
			err = compareError
		}
	}
	if err != nil {
		go middleware.LogError(request, err)
	}
	go middleware.LogLoginAttempt(request, username, succeed)
	return user, succeed
}

func (middleware *Middleware) GenerateCookieFor(request *http.Request, user *objects.User) (string, bool) {
	cookie, sessionCreationError := middleware.LoginSessions.CreateSession(user, 24*time.Hour)
	if sessionCreationError != nil {
		go middleware.LogError(request, sessionCreationError)
		return "", false
	}
	go middleware.LogCookieGeneration(request, user)
	return cookie, true
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
