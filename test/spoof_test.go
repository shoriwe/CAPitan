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

func TestValidInput(t *testing.T) {
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
	// Get arp spoof interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPSpoof, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPSpoofInterface\\(this\\.id\\)\"").FindAll(body, -1)
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
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPSpoof + "?action=" + actions.Spoof
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			TargetIP      string
			Gateway       string
			InterfaceName string
		}{
			TargetIP:      "192.168.1.1",
			Gateway:       "192.168.1.1",
			InterfaceName: interfaceName,
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

func TestInvalidTargetIP(t *testing.T) {
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
	// Get arp spoof interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPSpoof, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPSpoofInterface\\(this\\.id\\)\"").FindAll(body, -1)
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
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPSpoof + "?action=" + actions.Spoof
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			TargetIP      string
			Gateway       string
			InterfaceName string
		}{
			TargetIP:      "192.168.1.aaaa",
			Gateway:       "192.168.1.1",
			InterfaceName: interfaceName,
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
	if status.Succeed || status.Message != "Invalid IP provided" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestInvalidGateway(t *testing.T) {
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
	// Get arp spoof interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPSpoof, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPSpoofInterface\\(this\\.id\\)\"").FindAll(body, -1)
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
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPSpoof + "?action=" + actions.Spoof
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			TargetIP      string
			Gateway       string
			InterfaceName string
		}{
			TargetIP:      "192.168.1.1",
			Gateway:       "invalid",
			InterfaceName: interfaceName,
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
	if status.Succeed || status.Message != "Invalid Gateway IP provided" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestInvalidInterface(t *testing.T) {
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
	// Get arp spoof interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserARPSpoof, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectARPSpoofInterface\\(this\\.id\\)\"").FindAll(body, -1)
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
	websocketURL := "ws://" + hostUrl.Host + symbols.UserARPSpoof + "?action=" + actions.Spoof
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			TargetIP      string
			Gateway       string
			InterfaceName string
		}{
			TargetIP:      "192.168.1.1",
			Gateway:       "192.168.1.1",
			InterfaceName: interfaceName + "Invalid Interface",
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
	if status.Succeed || status.Message != "No permissions for selected interface" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}
