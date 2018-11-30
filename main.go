package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"bytes"
	"encoding/json"
	"time"

  "github.com/gorilla/sessions"
  "github.com/dgrijalva/jwt-go"
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
	auth_server = os.Getenv("AUTH_SERVER")
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

func listCredentials(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
  // api call to make
  api_url := "/api/v1/data?name-like="
  param1, ok := r.URL.Query()["search"]
  if ok {
    api_url = api_url+param1[0]
  }

  // set up netClient for use later
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  // use template
  tmpl := template.Must(template.ParseFiles("credentials.html", "base.html"))
	// Check if user is authenticated, forbid if not
  auth, _ := session.Values["authenticated"].(bool)
	if auth == false {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/login'\" />")
    return
	}
  access_token := session.Values["access_token"].(string)
  //claims := jwt.MapClaims{}
  var p jwt.Parser
  token, _, _ := p.ParseUnverified(access_token, &jwt.StandardClaims{})
  if err := token.Claims.Valid(); err != nil {
    fmt.Println("invalid")
  	session.Values["authenticated"] = false
  	session.Values["access_token"] = ""
  	session.Save(r, w)
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/login'\" />")
    return
  }


  // call the credhub api to get all credentials
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	req, _ := http.NewRequest("GET", auth_server+api_url, bytes.NewBuffer([]byte("")))
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

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)
  fmt.Println("logout")
	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["access_token"] = ""
	session.Save(r, w)
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/login'\" />")
  return
  //http.Redirect(w, r, "/login", 301)
}

func login(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
	tmpl := template.Must(template.ParseFiles("login.html"))
  //already authd, render tmpl
  //if session.Values["authenticated"].(bool) == true {
  auth, _ := session.Values["authenticated"].(bool)
  if auth == true {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
    return
	}

  //if not authd and not a POST, render tmpl
	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}
  // collect credentials from form
	loginCreds := ClientStruct{
		ClientID:     r.FormValue("client-id"),
		ClientSecret: r.FormValue("client-secret"),
	}
	// get auth url from server
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err := http.Get(auth_server + "/info")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	//fmt.Println("get:\n", string(body))
	authRespBytes := []byte(body)
	authResp := AuthServerResponse{}
  if authServErr := json.Unmarshal([]byte(authRespBytes), &authResp); err != nil {
    fmt.Println(authServErr)
  }
	oauth_server := authResp.AuthServer.URL

	// post auth request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err = http.PostForm(oauth_server+"/oauth/token", url.Values{
		"client_id": {loginCreds.ClientID},
		"client_secret": {loginCreds.ClientSecret},
		"grant_type": {"client_credentials"},
		"response_type": {"token"},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	//fmt.Println("post:\n", string(body))
	textBytes := []byte(body)
	list := AuthResponse{}
  if err := json.Unmarshal([]byte(textBytes), &list); err != nil {
    fmt.Println(err)
  }
	// Authentication goes here
	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Values["access_token"] = list.AccessToken
	session.Save(r, w)

	tmpl.Execute(w, struct{ Success bool }{true})
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/", listCredentials)

	//http.ListenAndServe(":8080", nil)
  err := http.ListenAndServe(":8080", logRequest(http.DefaultServeMux))
	if err != nil {
		fmt.Println(err)
	}
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
