package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"bytes"
	"encoding/json"
	"time"

  "github.com/gorilla/sessions"
)

type ClientStruct struct {
	ClientID     string
	ClientSecret string
}

type AuthResponse struct {
	AccessToken     string `json:"access_token"`
	Expiry int `json:"expires_in"`
	TokenType string `json:"token_type"`
	Scope string `json:"scope"`
	Error string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

type AuthServerResponse struct {
	AuthServer struct {
		URL string `json:"url"`
	} `json:"auth-server"`
	App struct {
		Name string `json:"name"`
	} `json:"app"`
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key         = []byte("super-secret-key")
	store       = sessions.NewCookieStore(key)
	credhub_server = os.Getenv("CREDHUB_SERVER")
	cookie_name = "auth-cookie"
)

type CredentialsData struct {
	Credentials []struct {
		VersionCreatedAt time.Time `json:"version_created_at"`
		Name             string    `json:"name"`
	} `json:"credentials"`
}

type CredentialPageData struct {
	PageTitle string
	Credentials     []CredentialsData
}

func ListCredentials(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
  // api call to make
  api_query := "/api/v1/data?name-like="
  //if we get a search query, add it to the api_query
  param1, ok := r.URL.Query()["search"]
  if ok {
    api_query = api_query+param1[0]
  }

  // use template
  tmpl := template.Must(template.ParseFiles("templates/credentials.html", "templates/base.html"))
	// Check if user is authenticated
  ValidateAuthSessionFalse(session, w, r)
  access_token := session.Values["access_token"].(string)

  //validate token
  ValidateAuthToken(session, access_token, w, r)

  // call the credhub api to get all credentials
  // set up netClient for use later
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	req, _ := http.NewRequest("GET", credhub_server+api_query, bytes.NewBuffer([]byte("")))
	req.Header.Add("authorization", "bearer "+access_token)
	req.Header.Set("Content-Type", "application/json")
	resp, reqErr := netClient.Do(req)
  if reqErr != nil {
    fmt.Println(reqErr)
  	http.Error(w, "Error", http.StatusBadRequest)
  	return
  }
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	credRespBytes := []byte(body)
	credResp := CredentialsData{}
  if credServErr := json.Unmarshal([]byte(credRespBytes), &credResp); credServErr != nil {
    fmt.Println(credServErr)
  }
  data := CredentialPageData{
		PageTitle: "Credentials",
		Credentials: []CredentialsData{
      credResp,
    },
	}
	tmpl.ExecuteTemplate(w, "base", data)
}

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "favicon.ico")
}

func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/", ListCredentials)
	http.HandleFunc("/get", GetCredentials)
  http.HandleFunc("/favicon.ico", FaviconHandler)

	//http.ListenAndServe(":8080", nil)
  //err := http.ListenAndServe(":8080", LogRequest(http.DefaultServeMux))
  err := http.ListenAndServeTLS(":8443", "server.crt", "server.key", LogRequest(http.DefaultServeMux))
	if err != nil {
		fmt.Println(err)
	}
}

func LogRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
