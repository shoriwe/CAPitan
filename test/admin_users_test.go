package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestCreateNewUser(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
}

func TestChangeUserPassword(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Change password
	data = url.Values{
		symbols.Username: {"sulcud"},
		symbols.Password: {"password"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdatePassword, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Enable the user'
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.IsAdmin:   {""},
		symbols.IsEnabled: {"on"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdateStatus, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if can login
	response, requestError = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"sulcud"},
			"password": []string{"password"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err = response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
}

func TestUserStatus(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Change password
	data = url.Values{
		symbols.Username: {"sulcud"},
		symbols.Password: {"password"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdatePassword, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Enable the user
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.IsAdmin:   {""},
		symbols.IsEnabled: {"on"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdateStatus, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if can login
	response, requestError = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"sulcud"},
			"password": []string{"password"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err = response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	// Make it Admin
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.IsAdmin:   {"on"},
		symbols.IsEnabled: {"on"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdateStatus, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Login and check if it has admin privs
	response, requestError = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"sulcud"},
			"password": []string{"password"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err = response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	//
	cookies = response.Cookies()
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.Dashboard, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile("Admin").Match(body) {
		t.Fatal(string(body))
	}
	// Disable the user
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.IsAdmin:   {""},
		symbols.IsEnabled: {""},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.UpdateStatus, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check it is disabled (Should fail to login)
	response, requestError = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"sulcud"},
			"password": []string{"password"},
		},
	)
	if requestError != nil {
		t.Fatal(requestError)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response)
	}
	location, err = response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Path == symbols.Dashboard {
		t.Fatal(location.Path)
	}
}

func TestCaptureInterfaceAddPermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"capture-interface-\\S+\"").Find(body)[25:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddCaptureInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(body))
	}
}

func TestCaptureInterfaceDeletePermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"capture-interface-\\S+\"").Find(body)[25:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddCaptureInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(body))
	}
	// Remove permission
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.DeleteCaptureInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if permission was removed
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	if strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(body))
	}
}

func TestARPScanInterfaceAddPermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"arp-scan-interface-\\S+\"").Find(body)[26:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddARPScanInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(interfaceName), string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(interfaceName), string(body))
	}
}

func TestARPScanInterfaceDeletePermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"arp-scan-interface-\\S+\"").Find(body)[26:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddARPScanInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(interfaceName), string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(interfaceName), string(body))
	}
	// Remove permission
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.DeleteARPScanInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if permission was removed
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	if strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(body))
	}
}

func TestARPSpoofInterfaceAddPermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"arp-spoof-interface-\\S+\"").Find(body)[27:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddARPSpoofInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(interfaceName), string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(interfaceName), string(body))
	}
}

func TestARPSpoofInterfaceDeletePermission(t *testing.T) {
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
	cookies := response.Cookies()
	data := url.Values{
		"username": []string{"sulcud"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.NewUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// List users and check if the new one is present
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.AdminEditUsers, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	// Get the name of any interface
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	interfaceName := regexp.MustCompile("<a id=\"arp-spoof-interface-\\S+\"").Find(body)[27:]
	interfaceName = interfaceName[:len(interfaceName)-1]
	// Add interface to capture permissions
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.AddARPSpoofInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if the interface was added
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(interfaceName), string(body))
	}
	if !strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(interfaceName), string(body))
	}
	// Remove permission
	data = url.Values{
		symbols.Username:  {"sulcud"},
		symbols.Interface: {string(interfaceName)},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.DeleteARPSpoofInterface, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	// Check if permission was removed
	data = url.Values{
		symbols.Username: {"sulcud"},
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.EditUser, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if !regexp.MustCompile("sulcud").Match(body) {
		t.Fatal(string(body))
	}
	if strings.Contains(string(body), fmt.Sprintf("<h3 class=\"interface-name\">%s</h3>", interfaceName)) {
		t.Fatal(string(body))
	}
}

func TestTestUser(t *testing.T) {
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
	cookies := response.Cookies()
	// check if admin exists
	payload := struct {
		Username string
	}{
		Username: "admin",
	}
	bytesPayload, marshalError := json.Marshal(payload)
	if marshalError != nil {
		t.Fatal(marshalError)
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.TestUser, bytes.NewReader(bytesPayload))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/json")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if string(body) != "{\"Found\":true}" {
		t.Fatal(string(body))
	}
	// Search for a user that does not exist
	payload = struct {
		Username string
	}{
		Username: "shoriwe",
	}
	bytesPayload, marshalError = json.Marshal(payload)
	if marshalError != nil {
		t.Fatal(marshalError)
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+symbols.AdminEditUsers+"?action="+actions.TestUser, bytes.NewReader(bytesPayload))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/json")
	response, requestError = client.Do(request)
	if requestError != nil {
		t.Fatal(requestError)
	}
	body, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	if string(body) == "{\"Found\":true}" {
		t.Fatal(string(body))
	}
}
