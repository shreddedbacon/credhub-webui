package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
)

type LoginStruct struct {
	Success bool
	Flash   string
}

type Flash struct {
	Type    string
	Message string
	Display bool
}

type ClientStruct struct {
	Username string
	Password string
}

func Login(w http.ResponseWriter, r *http.Request) {
	session := GetSession(w, r, cookieName)
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
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	// get auth url from server
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	resp, err := http.Get(credhubServer + "/info")
	if err != nil {
		flash := Flash{
			Type:    "warning",
			Message: "Error connecting to authorization server",
		}
		response := LoginStruct{
			Flash: flash.Message,
		}
		tmpl.Execute(w, response)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	authRespBytes := []byte(body)
	authResp := AuthServerResponse{}
	if authServErr := json.Unmarshal([]byte(authRespBytes), &authResp); err != nil {
		fmt.Println(authServErr)
	}
	oAuthServer := authResp.AuthServer.URL

	// post auth request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
	resp, err = http.PostForm(oAuthServer+"/oauth/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {loginCreds.Username},
		"password":      {loginCreds.Password},
		"grant_type":    {"password"},
		"response_type": {"token"},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ = ioutil.ReadAll(resp.Body)
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
				Flash:   flash.Message,
			}
			tmpl.Execute(w, response)
		}
		response := LoginStruct{
			Success: true,
		}
		tmpl.Execute(w, response)
	}
	flashes := session.Flashes()
	if len(flashes) > 0 {
		flash := flashes[0].(Flash)
		response := LoginStruct{
			Flash: flash.Message,
		}
		tmpl.Execute(w, response)
	} else {
		tmpl.Execute(w, nil)
	}
	return
}

func Logout(w http.ResponseWriter, r *http.Request) {
	//can this be done better?
	session := GetSession(w, r, cookieName)
	session.Values["access_token"] = ""
	session.Save(r, w)
	RedirectLogin(w, r)
	return
}

func ValidateAuthSession(session *sessions.Session, w http.ResponseWriter, r *http.Request) {
	accessToken, _ := session.Values["access_token"].(string)
	if accessToken != "" {
		var p jwt.Parser
		token, _, _ := p.ParseUnverified(accessToken, &jwt.StandardClaims{})
		if err := token.Claims.Valid(); err == nil {
			RedirectHome(w, r)
		}
	}
	return
}
