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
  session := GetSession(w, r)
	tmpl := template.Must(template.ParseFiles("templates/login.html"))

  //already authd, render tmpl
  ValidateAuthSession(session, w, r)

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
	authRespBytes := []byte(body)
	authResp := AuthServerResponse{}
  if authServErr := json.Unmarshal([]byte(authRespBytes), &authResp); err != nil {
    fmt.Println(authServErr)
  }
	oauth_server := authResp.AuthServer.URL

	// post auth request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
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
  //can this be done better?
  session := GetSession(w, r)
	session.Values["access_token"] = ""
	session.Save(r, w)
  RedirectLogin(w)
  return
}

func ValidateAuthSession(session *sessions.Session, w http.ResponseWriter, r *http.Request) {
  accessToken, _ := session.Values["access_token"].(string)
  if accessToken != "" {
    var p jwt.Parser
    token, _, _ := p.ParseUnverified(accessToken, &jwt.StandardClaims{})
    if err := token.Claims.Valid(); err != nil {
      //invalid
      return
    } else {
      //valid
      RedirectHome(w)
      return
    }
    return
  }
  return
}
