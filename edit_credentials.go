package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"time"
)
/*
  get a credential from CredHub
*/
func EditCredentials(w http.ResponseWriter, r *http.Request) {
	session := GetSession(w, r, cookieName)
	// api call to make
	apiQuery := "/api/v1/data?name="
	//if we get a search query, add it to the apiQuery
	param1, ok := r.URL.Query()["name"]
	if ok {
		apiQuery = apiQuery + param1[0]
	}
	accessToken := session.Values["access_token"].(string)
	// call the credhub api to get all credentials
	// set up netClient for use later
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	req, _ := http.NewRequest("GET", credhubServer+apiQuery, bytes.NewBuffer([]byte("")))
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
	credRespBytes := []byte(body)
	credResp := GetCredential{}
	if credServErr := json.Unmarshal([]byte(credRespBytes), &credResp); credServErr != nil {
		fmt.Println(credServErr)
	}
	flashsession := GetSession(w, r, "flash-cookie")
	flashes := flashsession.Flashes()
	flash := Flash{
		Display: false,
	}
	if len(flashes) > 0 {
		flash = flashes[0].(Flash)
		fmt.Println(flash)
	}
	for _, cred := range credResp.Data {
		switch cred.Type {
		case "rsa":
			credRespSSH := GetCredentialSSH{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespSSH); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageDataSSH{
				PageTitle: "RSA Credential",
				Credentials: []GetCredentialSSH{
					credRespSSH,
				},
				Flash: flash,
			}
			tmpl := template.Must(template.ParseFiles("templates/edit/rsa.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		case "ssh":
			credRespSSH := GetCredentialSSH{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespSSH); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageDataSSH{
				PageTitle: "SSH Credential",
				Credentials: []GetCredentialSSH{
					credRespSSH,
				},
				Flash: flash,
			}
			tmpl := template.Must(template.ParseFiles("templates/edit/ssh.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		case "certificate":
			credRespCert := GetCredentialCert{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespCert); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageDataCert{
				PageTitle: "Certificate Credential",
				Credentials: []GetCredentialCert{
					credRespCert,
				},
				Flash: flash,
			}
			tf := template.FuncMap{
				"CertNotAfter":   CertNotAfter,
				"CertCommonName": CertCommonName,
			}
			tmpl := template.Must(template.New("certificate.html").Funcs(tf).ParseFiles("templates/edit/certificate.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		case "user":
			credRespUser := GetCredentialUser{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespUser); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageDataUser{
				PageTitle: "User Credential",
				Credentials: []GetCredentialUser{
					credRespUser,
				},
				Flash: flash,
			}
			tmpl := template.Must(template.ParseFiles("templates/edit/user.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		case "json":
			credRespJson := GetCredentialJson{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespJson); credServErr != nil {
				fmt.Println(credServErr)
			}
			data3 := GetCredentialPageDataJson{
				PageTitle: "JSON Credential",
				Credentials: []GetCredentialJson{
					credRespJson,
				},
				Flash: flash,
			}
			tf := template.FuncMap{
				"MapToString": MapToString,
			}
			tmpl := template.Must(template.New("json.html").Funcs(tf).ParseFiles("templates/edit/json.html"))
			tmpl.ExecuteTemplate(w, "base", data3)
			return
		case "password":
			credRespdata := GetCredentialData{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespdata); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageData{
				PageTitle: "Password Credential",
				Credentials: []GetCredentialData{
					credRespdata,
				},
				Flash: flash,
			}
			tmpl := template.Must(template.ParseFiles("templates/edit/password.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		default:
			credRespdata := GetCredentialData{}
			if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespdata); credServErr != nil {
				fmt.Println(credServErr)
			}
			data := GetCredentialPageData{
				PageTitle: "Other Credential",
				Credentials: []GetCredentialData{
					credRespdata,
				},
				Flash: flash,
			}
			tmpl := template.Must(template.ParseFiles("templates/edit/value.html"))
			tmpl.ExecuteTemplate(w, "base", data)
			return
		}
	}
	// go home if no conditions met
	RedirectHome(w, r)
	return
}
