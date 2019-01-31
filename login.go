package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
)

type LoginStruct struct {
	Success     bool
	Flash       Flash
	CallbackUrl string
	AuthUrl     string
  ClientID    string
}

type Flash struct {
	Type    template.JS
	Message string
	Display bool
}

type ClientStruct struct {
	ClientID     string
	ClientSecret string
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}

/*
  login function
*/
func Login(w http.ResponseWriter, r *http.Request) {
	session := GetSession(w, r, cookieName)
	tmpl := template.Must(template.ParseFiles("templates/login.html"))

	//already authd, render tmpl
	ValidateAuthSession(session, w, r)

	flashsession := GetSession(w, r, "flash-cookie")
	flashes := flashsession.Flashes()
	var flash Flash
	if len(flashes) > 0 {
		flash = flashes[0].(Flash)
	}
	err := flashsession.Save(r, w)
	if err != nil {
		fmt.Println(err)
	}

	// get auth url from server
	oAuthServer, authErr := GetOauthServer()
	if authErr != nil {
		tmpl.Execute(w, authErr)
		RedirectHome(w, r) //FIX go to login and display error
		return
	}

	//if not authd and not a POST, render tmpl
	if r.Method != http.MethodPost {
		response := LoginStruct{
			CallbackUrl: uiUrl,
			AuthUrl:     oAuthServer,
			Flash:       flash,
      ClientID:    clientID,
		}
		tmpl.Execute(w, response)
		return
	}
	// collect credentials from form
	loginCreds := ClientStruct{
		ClientID:     r.FormValue("clientid"),
		ClientSecret: r.FormValue("clientsecret"),
	}

	// post auth request
	resp, err := http.PostForm(oAuthServer+"/oauth/token", url.Values{
		"client_id":     {loginCreds.ClientID},
		"client_secret": {loginCreds.ClientSecret},
		"grant_type":    {"client_credentials"},
		"response_type": {"token"},
		"token_format":  {"jwt"},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	textBytes := []byte(body)
	list := AuthResponse{}
	if err := json.Unmarshal([]byte(textBytes), &list); err != nil {
		fmt.Println(err)
	}
	if list.Error != "" {
		flash := Flash{
			Type:    "notice",
			Message: list.ErrorDesc,
			Display: true,
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
				Success:     true,
				Flash:       flash,
				CallbackUrl: uiUrl,
				AuthUrl:     oAuthServer,
        ClientID:    clientID,
			}
			tmpl.Execute(w, response)
		}
		response := LoginStruct{
			Success:     true,
			CallbackUrl: uiUrl,
			AuthUrl:     oAuthServer,
      ClientID:    clientID,
		}
		tmpl.Execute(w, response)
	}
	flashes = session.Flashes()
	if len(flashes) > 0 {
		flash := flashes[0].(Flash)
		response := LoginStruct{
			Flash:       flash,
			CallbackUrl: uiUrl,
			AuthUrl:     oAuthServer,
      ClientID:    clientID,
		}
		tmpl.Execute(w, response)
	} else {
		tmpl.Execute(w, nil)
	}
	return
}

/*
  Logout
*/
func Logout(w http.ResponseWriter, r *http.Request) {
	//can this be done better?
	session := GetSession(w, r, cookieName)
	session.Values["access_token"] = ""
	session.Save(r, w)
	RedirectLogin(w, r)
	return
}

/*
  call back function to interact with uaa
*/
func LoginCallback(w http.ResponseWriter, r *http.Request) {
	httpClient := http.Client{}
	session := GetSession(w, r, cookieName)
	param, ok := r.URL.Query()["error_description"]
	if ok {
		respParam := strings.Join(param, "")
		AddFlash(w, r, respParam, "warning")
		RedirectLogin(w, r)
		return
	}
	// get auth url from server
	oAuthServer, err := GetOauthServer()
	if err != nil {
		RedirectHome(w, r) //FIX go to login and display error
		return
	}

	// get code from query params
	parseErr := r.ParseForm()
	if parseErr != nil {
		fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}
	code := r.FormValue("code")
	// call the uaa auth endpoint
	reqURL := fmt.Sprintf("%s/oauth/token?client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s/login/callback", oAuthServer, clientID, clientSecret, code, uiUrl)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}
	req.Header.Set("accept", "application/json")
	req.SetBasicAuth(clientID, clientSecret)

	// Send out the HTTP request
	res, err := httpClient.Do(req)
	reqBody, _ := ioutil.ReadAll(res.Body)
	textBytes := []byte(reqBody)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	defer res.Body.Close()

	// Parse the request body into the `OAuthAccessResponse` struct
	var t OAuthAccessResponse
	if err := json.Unmarshal([]byte(textBytes), &t); err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
	}
	session.Values["access_token"] = t.AccessToken
	session.Save(r, w)
	// go home now
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
}

/*
  validate session on login page without redirect loop
*/
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

func GetOauthServer() (string, interface{}) {
	// get auth url from server
	resp, err := http.Get(credhubServer + "/info")
	if err != nil {
		flash := Flash{
			Type:    "warning",
			Message: "Error connecting to authorization server",
			Display: true,
		}
		response := LoginStruct{
			Flash: flash,
		}
		return "", response
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	authRespBytes := []byte(body)
	authResp := AuthServerResponse{}
	if authServErr := json.Unmarshal([]byte(authRespBytes), &authResp); err != nil {
		fmt.Println(authServErr)
	}
	oAuthServer := authResp.AuthServer.URL
	return oAuthServer, nil
}
