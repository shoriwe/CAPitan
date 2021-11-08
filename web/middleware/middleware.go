package middleware

import (
	"embed"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/sessions"
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
			http.Redirect(responseWriter, request, context.Redirect, context.StatusCode)
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
	user, loginError := middleware.Database.Login(username, password)
	if loginError != nil {
		go middleware.LogError(request, loginError)
		return nil, false
	}
	succeed := user != nil
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