package test

import (
	"github.com/shoriwe/CAPitan/internal/web/symbols"
	"github.com/shoriwe/CAPitan/internal/web/symbols/actions"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

func TestUpdateSecurityQuestion(t *testing.T) {
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
		"password": []string{"admin"},
		"question": []string{"My question"},
		"answer":   []string{"Its answer"},
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+symbols.UpdateSecurityQuestion, strings.NewReader(data.Encode()))
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
	response, err = client.PostForm(
		server.URL+symbols.ResetPassword+"?action="+actions.GetQuestion,
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
		server.URL+symbols.ResetPassword+"?action="+actions.AnswerQuestion,
		url.Values{
			"key":    []string{key},
			"answer": []string{"Its answer"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	var contents []byte
	contents, readError = io.ReadAll(response.Body)
	if readError != nil {
		t.Fatal(readError)
	}
	result := regexp.MustCompile("Your password is: \\w+").Find(contents)
	newPassword := strings.Split(string(result), ": ")[1]
	// Login with the new creds
	response, err = client.PostForm(
		server.URL+symbols.Login,
		url.Values{
			"username": []string{"admin"},
			"password": []string{newPassword},
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
	if location.Path != symbols.Dashboard {
		t.Fatal(location.Path)
	}
}
