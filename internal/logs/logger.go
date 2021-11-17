package logs

import (
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

func (logger *Logger) LogLoginAttempt(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("%s succeed login as %s", request.RemoteAddr, username)
	} else {
		logger.debugLogger.Printf("%s failed login as %s", request.RemoteAddr, username)
	}
}

func (logger *Logger) LogCookieGeneration(request *http.Request, username string) {
	logger.debugLogger.Printf("cookie generated for %s -> %s", username, request.RemoteAddr)
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

func (logger *Logger) LogSystemUpdatePassword(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully force password update for %s", username)
	} else {
		logger.debugLogger.Printf("Failed to force password update for %s", username)
	}
}

func (logger *Logger) LogUpdatePassword(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully updated password for %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to updated password for %s by %s", username, request.RemoteAddr)
	}
}

func (logger *Logger) LogUpdateSecurityQuestion(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully updated security question for %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to updated security question for %s by %s", username, request.RemoteAddr)
	}
}

func NewLogger(logWriter io.Writer) *Logger {
	return &Logger{
		errorLogger: log.New(logWriter, "ERROR: ", log.Ldate|log.Ltime),
		debugLogger: log.New(logWriter, "DEBUG: ", log.Ldate|log.Ltime),
	}
}
