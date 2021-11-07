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

func (logger *Logger) LogLoginAttempt(request *http.Request, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("%s succeed login as %s", request.RemoteAddr, request.PostForm.Get("username"))
	} else {
		logger.debugLogger.Printf("%s failed login as %s", request.RemoteAddr, request.PostForm.Get("username"))
	}
}

func NewLogger(logWriter io.Writer) *Logger {
	return &Logger{
		errorLogger: log.New(logWriter, "ERROR: ", log.Ldate|log.Ltime),
		debugLogger: log.New(logWriter, "DEBUG: ", log.Ldate|log.Ltime),
	}
}
