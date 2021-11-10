package logs

import (
	"github.com/shoriwe/CAPitan/data/objects"
	"io"
	"log"
	"net/http"
)

type Logger struct {
	errorLogger *log.Logger
	debugLogger *log.Logger
}

func (logger *Logger) LogError(request *http.Request, err error) {
	logger.errorLogger.Printf("%s %s %s", request.RemoteAddr, request.RequestURI, err)
}

func (logger *Logger) LogVisit(request *http.Request) {
	logger.debugLogger.Printf("%s %s %s", request.RemoteAddr, request.Method, request.RequestURI)
}

func (logger *Logger) LogLoginAttempt(request *http.Request, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("%s succeed login as %s", request.RemoteAddr, request.PostFormValue("username"))
	} else {
		logger.debugLogger.Printf("%s failed login", request.RemoteAddr)
	}
}

func (logger *Logger) LogCookieGeneration(request *http.Request, user *objects.User) {
	logger.debugLogger.Printf("cookie generated for %s -> %s", user.Username, request.RemoteAddr)
}

func (logger *Logger) LogAuthRequired(request *http.Request) {
	logger.debugLogger.Printf("request from %s to %s blocked AUTH REQUIRED", request.RemoteAddr, request.RequestURI)
}

func (logger *Logger) LogMethodNotAllowed(request *http.Request) {
	logger.debugLogger.Printf("%s %s not allowed for %s", request.RemoteAddr, request.Method, request.RequestURI)
}

func (logger *Logger) LogBannedByLimit(request *http.Request) {
	logger.debugLogger.Printf("Banned %s cause of limit exceed of path %s", request.RemoteAddr, request.RequestURI)
}

func (logger *Logger) LogUserNotFound(request *http.Request, username string) {
	logger.debugLogger.Printf("User %s requested %s by not found", username, request.RemoteAddr)
}

func NewLogger(logWriter io.Writer) *Logger {
	return &Logger{
		errorLogger: log.New(logWriter, "ERROR: ", log.Ldate|log.Ltime),
		debugLogger: log.New(logWriter, "DEBUG: ", log.Ldate|log.Ltime),
	}
}
