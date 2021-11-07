package middleware

import (
	"embed"
	"github.com/shoriwe/CAPitan/data"
	"github.com/shoriwe/CAPitan/data/objects"
	"github.com/shoriwe/CAPitan/logs"
	"net/http"
)

type (
	Context struct {
		StatusCode int
		Headers    map[string]string
		Body       string
		User       interface{}
	}
	HandleFunc func(middleware *Middleware, context *Context, request *http.Request) bool
	Middleware struct {
		// dataController   data.Database
		// logger *logs.Logger
		data.Database
		*logs.Logger
		Templates embed.FS
	}
)

func NewContext() *Context {
	return &Context{
		StatusCode: http.StatusOK,
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
		responseWriter.WriteHeader(context.StatusCode)
		_, writeError := responseWriter.Write([]byte(context.Body))
		if writeError != nil {
			middleware.LogError(request, writeError)
		}
	}
}

func (middleware *Middleware) Login(request *http.Request, username string, password string) (*objects.User, bool) {
	user, loginError := middleware.Database.Login(username, password)
	if loginError != nil {
		middleware.LogError(request, loginError)
		return nil, false
	}
	succeed := user != nil
	// TODO: Log the login attempt
	middleware.LogLoginAttempt(request, succeed)
	return user, succeed
}
