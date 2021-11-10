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

const TwentyFourHours = 24 * time.Hour

type (
	Context struct {
		StatusCode int
		Redirect   string
		Headers    map[string]string
		Body       string
		User       *objects.User
	}
	HandleFunc func(middleware *Middleware, context *Context, request *http.Request) bool
	Middleware struct {
		// dataController   data.Database
		// logger *logs.Logger
		data.Database
		*logs.Logger
		*sessions.Sessions
		*limit.Limiter
		Templates embed.FS
	}
)

func NewContext() *Context {
	return &Context{
		StatusCode: http.StatusOK,
		Redirect:   "",
		Headers:    map[string]string{},
		Body:       "",
		User:       nil,
	}
}

func New(c data.Database, l *logs.Logger, t embed.FS) *Middleware {
	return &Middleware{
		Database:  c,
		Logger:    l,
		Templates: t,
		Sessions:  sessions.NewSessions(),
		Limiter:   limit.NewLimiter(),
	}
}

func (middleware *Middleware) Handle(handlerFunctions ...HandleFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		context := NewContext()
		for _, handlerFunction := range handlerFunctions {
			if !handlerFunction(middleware, context, request) {
				break
			}
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

func (middleware *Middleware) Login(request *http.Request, username string, password string) (*objects.User, bool) {
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
	go middleware.LogLoginAttempt(request, succeed)
	return user, succeed
}

func (middleware *Middleware) GenerateCookieFor(request *http.Request, user *objects.User) (string, bool) {
	cookie, sessionCreationError := middleware.CreateSession(user, TwentyFourHours)
	if sessionCreationError != nil {
		middleware.LogError(request, sessionCreationError)
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
