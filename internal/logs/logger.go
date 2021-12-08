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
		logger.debugLogger.Printf("Successfully force password update for %s FROM %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to force password update for %s FROM %s", username, request.RemoteAddr)
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

func (logger *Logger) LogAdminRequired(request *http.Request, username string) {
	logger.debugLogger.Printf("request from %s to %s with username %s blocked ADMIN REQUIRED", request.RemoteAddr, request.RequestURI, username)
}

func (logger *Logger) LogUserCreation(request *http.Request, succeed bool, username string) {
	if succeed {
		logger.debugLogger.Printf("Successfully created user %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to create user %s by %s", username, request.RemoteAddr)
	}
}

func (logger *Logger) LogQueryUserPermissions(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully query permissions for user %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to query permissions for user %s by %s", username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminUpdatePassword(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully updated password for user %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed updated password for user %s by %s", username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminUpdateUserStatus(request *http.Request, username string, isAdmin, isEnabled, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully updated status (isAdmin: %t & isEnabled: %t) for user %s by %s", isAdmin, isEnabled, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed updated status (isAdmin: %t & isEnabled: %t) for user %s by %s", isAdmin, isEnabled, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminAddCapturePrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully added capture privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to add capture privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminDeleteCapturePrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully removed capture privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to remove capture privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminAddARPScanPrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully added arp scan privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to add arp scan privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminDeleteARPScanPrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully removed arp scan privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to remove arp scan privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminAddARPSpoofPrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully added arp spoof privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to add arp spoof privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogAdminDeleteARPSpoofPrivilege(request *http.Request, username string, i string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully removed arp spoof privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to remove arp spoof privilege for interface %s and user %s by %s", i, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogListUserCaptures(request *http.Request, username string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully listed captures for user %s by %s", username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to list captures for user %s by %s", username, request.RemoteAddr)
	}
}

func (logger *Logger) LogReserveCaptureNameForUser(request *http.Request, username, captureName string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully reserved capture name \"%s\" for user %s by %s", captureName, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to reserve capture name \"%s\" for user %s by %s", captureName, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogRemoveReserveCaptureNameForUser(request *http.Request, username, captureName string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully removed reserved capture name \"%s\" for user %s by %s", captureName, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed removed reserved capture name \"%s\" for user %s by %s", captureName, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogSaveInterfaceCapture(request *http.Request, username, captureName, interfaceName string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully saved capture with name \"%s\" targeting the interface %s started by user %s in %s", captureName, interfaceName, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to save capture with name \"%s\" targeting the interface %s started by user %s in %s", captureName, interfaceName, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogSaveImportCapture(request *http.Request, username, captureName string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully saved capture with name \"%s\" imported by user %s in %s", captureName, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to save capture with name \"%s\" imported by user %s in %s", captureName, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogQueryUserCapture(request *http.Request, username, captureName string, succeed bool) {
	if succeed {
		logger.debugLogger.Printf("Successfully queried %s for user %s at %s", captureName, username, request.RemoteAddr)
	} else {
		logger.debugLogger.Printf("Failed to query %s for user %s at %s", captureName, username, request.RemoteAddr)
	}
}

func (logger *Logger) LogARPSpoofStarted(request *http.Request, username, ip, gateway string) {
	logger.debugLogger.Printf("Successfully started ARP spoof by %s to IP %s and gateway %s at %s", username, ip, gateway, request.RemoteAddr)
}

func NewLogger(logWriter io.Writer) *Logger {
	return &Logger{
		errorLogger: log.New(logWriter, "ERROR: ", log.Ldate|log.Ltime),
		debugLogger: log.New(logWriter, "DEBUG: ", log.Ldate|log.Ltime),
	}
}
