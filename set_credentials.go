package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"html/template"
	"net/http"
	//"strconv"
	"io/ioutil"
	"strings"
	"time"
)

type SetCredentialValueStruct struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SetCredentialStruct struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value ValueParameters `json:"value"`
}

type ValueParameters struct {
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	CA          string `json:"ca,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
}

func SetCredentials(w http.ResponseWriter, r *http.Request) {
	session := GetSession(w, r, cookieName)
	muxvars := mux.Vars(r)
	credType := muxvars["credtype"]
	accessToken := session.Values["access_token"].(string)
	if r.Method == http.MethodPost {
		switch credType {
		case "value":
			credName := r.FormValue("name")
			r.ParseForm()
			value := strings.Join(r.Form["value"], "")
			//create payload
			setValue := SetCredentialValueStruct{
				Name:  credName,
				Type:  "value",
				Value: value,
			}
			PutCredentials(w, r, setValue, accessToken)
		case "password":
			credName := r.FormValue("name")
			r.ParseForm()
			value := strings.Join(r.Form["value"], "")
			//create payload
			setValue := SetCredentialValueStruct{
				Name:  credName,
				Type:  "password",
				Value: value,
			}
			PutCredentials(w, r, setValue, accessToken)
		case "user":
			credName := r.FormValue("name")
			r.ParseForm()
			username := strings.Join(r.Form["username"], "")
			password := strings.Join(r.Form["password"], "")
			//create payload
			values := ValueParameters{
				Username: username,
				Password: password,
			}
			setValue := SetCredentialStruct{
				Name:  credName,
				Type:  "user",
				Value: values,
			}
			PutCredentials(w, r, setValue, accessToken)
		case "certificate":
			credName := r.FormValue("name")
			r.ParseForm()
			ca := strings.Join(r.Form["ca"], "")
			certificate := strings.Join(r.Form["certificate"], "")
			privateKey := strings.Join(r.Form["private_key"], "")
			//create payload
			values := ValueParameters{
				CA:          ca,
				Certificate: certificate,
				PrivateKey:  privateKey,
			}
			setValue := SetCredentialStruct{
				Name:  credName,
				Type:  "certificate",
				Value: values,
			}
			PutCredentials(w, r, setValue, accessToken)
		default:
			RedirectHome(w, r)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		if stringInSlice(credType, []string{"password", "user", "certificate", "rsa", "ssh", "json", "value"}) {
			fmt.Println(credType)
			tmpl := template.Must(template.ParseFiles("templates/set/" + credType + ".html"))
			tmpl.ExecuteTemplate(w, "base", nil)
		} else {
			ReturnBlank(w)
		}
	}
	return
}

func PutCredentials(w http.ResponseWriter, r *http.Request, credential interface{}, accessToken string) {
	apiQuery := "/api/v1/data"
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
	jsonStr, _ := json.Marshal(credential)
	req, _ := http.NewRequest("PUT", credhubServer+apiQuery, bytes.NewBuffer(jsonStr))
	req.Header.Add("authorization", "bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, reqErr := netClient.Do(req)
	if reqErr != nil {
		fmt.Println(reqErr)
		http.Error(w, "Error", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	flashMessage := []byte(body)
	CheckError(w, r, flashMessage, "Successfully set credential", "success")
}
