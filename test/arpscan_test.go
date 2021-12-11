package test

import (
	"github.com/gorilla/websocket"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

func TestNewARPScanWithValidScript(t *testing.T) {
	const validScript = `
class Targets
	def Initialize()
		self.current = 0
	end

	def Next()
		host = "192.168.1." + self.current.ToString()
		self.current += 1
		return host
	end

	def HasNext()
		return self.current < 256
	end

	def Iter()
		return self
	end
end

LoadHostGenerator(Targets())
`
	// Login
	server := NewTestServer()
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, requestError := client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{"admin"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	// Prepare cookies
	cookies := response.Cookies()
	var cookiesHeader string
	for _, cookie := range cookies {
		cookiesHeader += cookie.String()
	}
	// Get arp scan interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPScan, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response)
	}
	//// Get any interface
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPScanInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new arp spoof
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPScan + "?action=" + actions.New
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			ScanName      string
			InterfaceName string
			Script        string
		}{
			ScanName:      "Test",
			InterfaceName: interfaceName,
			Script:        validScript,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Check if everything is ok
	var status struct {
		Succeed bool
		Message string
	}
	readError = connection.ReadJSON(&status)
	if readError != nil {
		t.Fatal(readError)
	}
	if !status.Succeed || status.Message != "Everything ok!" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewARPScanWithInvalidScript(t *testing.T) {
	const invalidScript = `[[[]]`
	// Login
	server := NewTestServer()
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, requestError := client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{"admin"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	// Prepare cookies
	cookies := response.Cookies()
	var cookiesHeader string
	for _, cookie := range cookies {
		cookiesHeader += cookie.String()
	}
	// Get arp scan interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPScan, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response)
	}
	//// Get any interface
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPScanInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new arp spoof
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPScan + "?action=" + actions.New
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			ScanName      string
			InterfaceName string
			Script        string
		}{
			ScanName:      "Test",
			InterfaceName: interfaceName,
			Script:        invalidScript,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Check if everything is ok
	var status struct {
		Succeed bool
		Message string
	}
	readError = connection.ReadJSON(&status)
	if readError != nil {
		t.Fatal(readError)
	}
	if status.Succeed || status.Message != "GoRuntimeError: SyntaxError: invalid definition of Array Expression at line 1" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewARPScanWithNameOfOldOne(t *testing.T) {
	const validScript = `
class Targets
	def Initialize()
		self.current = 0
	end

	def Next()
		host = "192.168.1." + self.current.ToString()
		self.current += 1
		return host
	end

	def HasNext()
		return self.current < 256
	end

	def Iter()
		return self
	end
end

LoadHostGenerator(Targets())
`
	// Login
	server := NewTestServer()
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, requestError := client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{"admin"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	// Prepare cookies
	cookies := response.Cookies()
	var cookiesHeader string
	for _, cookie := range cookies {
		cookiesHeader += cookie.String()
	}
	// Get arp scan interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPScan, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response)
	}
	//// Get any interface
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPScanInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new arp spoof
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPScan + "?action=" + actions.New
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			ScanName      string
			InterfaceName string
			Script        string
		}{
			ScanName:      "Test",
			InterfaceName: interfaceName,
			Script:        validScript,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Check if everything is ok
	var status struct {
		Succeed bool
		Message string
	}
	readError = connection.ReadJSON(&status)
	if readError != nil {
		t.Fatal(readError)
	}
	if !status.Succeed || status.Message != "Everything ok!" {
		t.Fatal(status.Message)
	}

	writeError = connection.WriteJSON(
		struct {
			Action string
		}{
			Action: symbols.StopSignal,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}

	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}

	// /// // ///

	// Start a new arp spoof
	header = http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ = url.Parse(server.URL)
	websocketURL = "ws://" + hostUrl.Host + symbols.UserARPScan + "?action=" + actions.New
	connection, _, dialError = websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError = connection.WriteJSON(
		struct {
			ScanName      string
			InterfaceName string
			Script        string
		}{
			ScanName:      "Test",
			InterfaceName: interfaceName,
			Script:        validScript,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Check if everything is ok
	readError = connection.ReadJSON(&status)
	if readError != nil {
		t.Fatal(readError)
	}
	if status.Succeed || status.Message != "Scan name already taken" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError = connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}
