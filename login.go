package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"encoding/json"

  "github.com/gorilla/sessions"
  "github.com/dgrijalva/jwt-go"
)

type LoginStruct struct {
	Success bool
	Flash   string
}

type Flash struct {
    Type    string
    Message string
}

func Login(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
	tmpl := template.Must(template.ParseFiles("templates/login.html"))

  //already authd, render tmpl
  ValidateAuthSessionTrue(session, w, r)

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
	resp, err := http.Get(credhub_server + "/info")
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
  if list.Error != "" {
    flash := Flash{
        Type:    "notice",
        Message: list.ErrorDesc,
    }
    session.AddFlash(flash)
  }
  if list.Error == "" {
  	// Authentication goes here
  	// Set user as authenticated
  	session.Values["authenticated"] = true
  	session.Values["access_token"] = list.AccessToken
  	session.Save(r, w)
    flashes := session.Flashes()
    if len(flashes) > 0 {
      flash := flashes[0].(Flash)
      response := LoginStruct{
        Success: true,
        Flash: flash.Message,
      }
      tmpl.Execute(w, response)
      return
    }
    response := LoginStruct{
      Success: true,
    }
    tmpl.Execute(w, response)
    return
  }
  flashes := session.Flashes()
  if len(flashes) > 0 {
      flash := flashes[0].(Flash)
      response := LoginStruct{
        Flash: flash.Message,
      }
      tmpl.Execute(w, response)
      return
  } else {
    tmpl.Execute(w, nil)
    return
  }
  tmpl.Execute(w, nil)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)
  fmt.Println("logout")
	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["access_token"] = ""
	session.Save(r, w)
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/login'\" />")
  return
}

func ValidateAuthToken(session *sessions.Session, access_token string, w http.ResponseWriter, r *http.Request) {
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
  return
}

func ValidateAuthSessionFalse(session *sessions.Session, w http.ResponseWriter, r *http.Request) {
  auth, _ := session.Values["authenticated"].(bool)
  if auth == false {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/login'\" />")
    return
  }
  return
}


func ValidateAuthSessionTrue(session *sessions.Session, w http.ResponseWriter, r *http.Request) {
  auth, _ := session.Values["authenticated"].(bool)
  if auth == true {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
    return
  }
  return
}
