package test

import (
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"
)

func TestLoginSucceed(t *testing.T) {
	server := NewTestServer()
	defer server.Close()
	client := &http.Client{}
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
}

func TestLoginFailed(t *testing.T) {
	server := NewTestServer()
	defer server.Close()
	client := &http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, requestError := client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{"wrong-password"},
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
	if location.Path != symbols.Login {
		t.Fatal(location.Path)
	}
}

func TestLogout(t *testing.T) {
	server := NewTestServer()
	defer server.Close()
	client := &http.Client{}
	client.Jar, _ = cookiejar.New(nil)
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
	// Logout
	request, _ := http.NewRequest(http.MethodGet, server.URL+symbols.Logout, nil)
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
	// Revisit Dashboard with cookies
	request, _ = http.NewRequest(http.MethodGet, server.URL+symbols.Dashboard, nil)
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
}

func TestResetPassword(t *testing.T) {
	server := NewTestServer()
	defer server.Close()
	client := &http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Reset password
	response, err := client.PostForm(
		server.URL+"/reset?action=get-question",
		url.Values{
			"username": []string{"admin"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	results := regexp.MustCompilePOSIX("name=\"key\".*$").FindAll(body, -1)
	if len(results) == 0 {
		t.Fatal("No key found")
	}
	rawKeyEntry := regexp.MustCompile("value\\=\\\"\\w+").Find(results[0])
	key := string(rawKeyEntry)[7:]

	response, err = client.PostForm(
		server.URL+"/reset?action=answer-question",
		url.Values{
			"key":    []string{key},
			"answer": []string{"admin"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatal(response.StatusCode)
	}
	location, locationError := response.Location()
	if locationError != nil {
		t.Fatal(locationError)
	}
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
	// Try to re-login but with the old credentials
	// WARNING: Login should fail
	response, err = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{"admin"},
		},
	)
	if err != nil {
		t.Fatal(err)
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
}
