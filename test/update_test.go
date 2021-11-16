package test

import (
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestUpdatePassword(t *testing.T) {
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
	// Update Password
	data := url.Values{
		"old":          []string{"admin"},
		"new":          []string{"password"},
		"confirmation": []string{"password"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.UpdatePassword, strings.NewReader(data.Encode()))
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestError = client.Do(request)

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
	if location.Path != symbols.Settings {
		t.Fatal(location.Path)
	}
	// Logout
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.Logout, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, requestError = client.Do(request)
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
	if location.Path != symbols.Login {
		t.Fatal(location.Path)
	}

	// Login again but with new password
	response, requestError = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
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
