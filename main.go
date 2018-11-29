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
)

type ClientStruct struct {
	ClientID     string
	ClientSecret string
}

func keepLines(s string, n int) string {
	result := strings.Join(strings.Split(s, "\n")[:n], "\n")
	return strings.Replace(result, "\r", "", -1)
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Print secret message
	fmt.Fprintln(w, "The cake is a lie!")
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Authentication goes here
	// ...

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

func root(w http.ResponseWriter, r *http.Request) {
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

	// get auth url
	auth_server := "http://google.com"
	resp, err := http.Get(auth_server)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println("get:\n", keepLines(string(body), 3))

	// post auth request
	auth_url := "https://google.com"
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err = http.PostForm(auth_url, url.Values{"q": {"github"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	fmt.Println("post:\n", keepLines(string(body), 3))

	session, _ := store.Get(r, "cookie-name")
	// Authentication goes here
	// ...
	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)

	tmpl.Execute(w, struct{ Success bool }{true})
}

func main() {
	http.HandleFunc("/", root)
	http.HandleFunc("/secret", secret)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", nil)
}
