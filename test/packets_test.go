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
	"time"
)

func TestNewCaptureWithValidScript(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
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
	if !status.Succeed || status.Message != "Everything ok" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureWithInvalidScript(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + [[[[[[[[[[[[[[`,
			Description:   "My description",
			CaptureName:   "Test",
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
	if status.Succeed || status.Message == "Everything ok" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureWithoutScript(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        ``,
			Description:   "My description",
			CaptureName:   "Test",
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
	if !status.Succeed || status.Message != "Everything ok" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureInvalidName(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "",
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
	if status.Succeed || status.Message == "Everything ok" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureInvalidDescription(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "",
			CaptureName:   "Test",
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
	if status.Succeed || status.Message == "Everything ok" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureUsingNameOfActiveOne(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
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
	if !status.Succeed || status.Message != "Everything ok" {
		t.Fatal(status.Message)
	}
	// Start the other capture with the same name
	// Start the second capture
	secondConnection, _, secondDialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if secondDialError != nil {
		t.Fatal(secondDialError)
	}
	writeError = secondConnection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
			InterfaceName: interfaceName,
		},
	)
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Check if everything is ok
	var secondStatus struct {
		Succeed bool
		Message string
	}
	readError = secondConnection.ReadJSON(&secondStatus)
	if readError != nil {
		t.Fatal(readError)
	}
	if secondStatus.Succeed || secondStatus.Message == "Everything ok" {
		t.Fatal(secondStatus.Message)
	}
	// Finish it
	closeError := secondConnection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
	// Finish the first connection
	closeError = connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}

func TestNewCaptureUsingNameOldOne(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	interfaceEntries := regexp.MustCompile("<a id=\".+\" onclick=\"selectCaptureInterface\\(this\\.id\\)\"").FindAll(body, -1)
	if len(interfaceEntries) == 0 {
		t.Fatal(string(body))
	}
	preInterfaceName := regexp.MustCompile("id\\=\\S+").Find(interfaceEntries[0])
	if len(preInterfaceName) <= 4 {
		t.Fatal(string(body))
	}
	interfaceName := string(preInterfaceName[4 : len(preInterfaceName)-1])
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
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
	if !status.Succeed || status.Message != "Everything ok" {
		t.Fatal(status.Message)
	}
	time.Sleep(5 * time.Second)
	writeError = connection.WriteJSON(struct {
		Action string
	}{
		Action: "STOP",
	})
	if writeError != nil {
		t.Fatal(writeError)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
	// Try to create a new capture with the same name
	// Start a new capture
	connection, _, dialError = websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError = connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
			InterfaceName: interfaceName,
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
	if status.Succeed || status.Message != "Capture name is already in use" {
		t.Fatal(status.Message)
	}
}

func TestNewCaptureWithNonPermittedInterface(t *testing.T) {
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
	// Get capture interface
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.UserPacketCaptures+"?action="+actions.New, nil)
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
	// Start a new capture
	header := http.Header{}
	header.Set("Cookie", cookiesHeader)
	hostUrl, _ := url.Parse(server.URL)
	websocketURL := "ws://" + hostUrl.Host + symbols.UserPacketCaptures + "?action=" + actions.Start
	connection, _, dialError := websocket.DefaultDialer.Dial(websocketURL, header)
	if dialError != nil {
		t.Fatal(dialError)
	}
	writeError := connection.WriteJSON(
		struct {
			Promiscuous   bool
			Script        string
			Description   string
			CaptureName   string
			InterfaceName string
		}{
			Promiscuous:   true,
			Script:        `1 + 1`,
			Description:   "My description",
			CaptureName:   "Test",
			InterfaceName: "interface",
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
	readError := connection.ReadJSON(&status)
	if readError != nil {
		t.Fatal(readError)
	}
	if status.Succeed || status.Message != "User do not have permission for the selected interface" {
		t.Fatal(status.Message)
	}
	// Finish it
	closeError := connection.Close()
	if closeError != nil {
		t.Fatal(closeError)
	}
}
