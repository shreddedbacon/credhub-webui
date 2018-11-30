package main

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/sessions"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"os"
	"bytes"
	"encoding/json"
	"time"
)

type ClientStruct struct {
	ClientID     string
	ClientSecret string
}

type AuthResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType string `json:"token_type"`
	Scope string `json:"scope"`
	Error string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key         = []byte("super-secret-key")
	store       = sessions.NewCookieStore(key)
	auth_server1 = os.Getenv("AUTH_SERVER1")
	auth_server2 = os.Getenv("AUTH_SERVER2")
	cookie_name = "auth-cookie"
)

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	req, _ := http.NewRequest("GET", auth_server1+"/api/v1/data?name-like=", bytes.NewBuffer([]byte("")))
	access_token := session.Values["access_token"].(string)
	req.Header.Add("authorization", "bearer "+access_token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := netClient.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("post:\n", string(body))
	// Print secret message
	fmt.Fprintln(w, string(body))
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["access_token"] = ""
	session.Save(r, w)
}

func login(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("login.html"))
	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}
	details := ClientStruct{
		ClientID:     r.FormValue("client-id"),
		ClientSecret: r.FormValue("client-secret"),
	}
	// do something with details
	_ = details
	fmt.Println(details)

	// get auth url (this needs to be fixed up a bit because its not really even being used yet to extract the url)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err := http.Get(auth_server1 + "/info")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println("get:\n", string(body))

	// post auth request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err = http.PostForm(auth_server2+"/oauth/token", url.Values{
		"client_id": {details.ClientID},
		"client_secret": {details.ClientSecret},
		"grant_type": {"client_credentials"},
		"response_type": {"token"},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	fmt.Println("post:\n", string(body))
	textBytes := []byte(body)
	list := AuthResponse{}
  if err := json.Unmarshal([]byte(textBytes), &list); err != nil {
    fmt.Println(err)
  }
	fmt.Println(list)
	session, _ := store.Get(r, cookie_name)
	// Authentication goes here
	// ...
	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Values["access_token"] = list.AccessToken
	session.Save(r, w)

	tmpl.Execute(w, struct{ Success bool }{true})
}

func main() {
	http.HandleFunc("/", login)
	http.HandleFunc("/secret", secret)
	http.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", nil)
}
