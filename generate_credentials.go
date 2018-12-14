package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type PasswordStruct struct {
	Name       string             `json:"name"`
	Type       string             `json:"type"`
	Parameters PasswordParameters `json:"parameters"`
}

type PasswordParameters struct {
	ExcludeUpper     bool   `json:"exclude_upper,omitempty"`
	ExcludeLower     bool   `json:"exclude_lower,omitempty"`
	ExcludeNumber    bool   `json:"exclude_number,omitempty"`
	IncludeSpecial   bool   `json:"include_special,omitempty"`
	Username         string `json:"username,omitempty"`
	Length           int    `json:"length,omitempty"`
	CommonName       string `json:"common_name,omitempty"`
	AlternativeNames string `json:"alternative_names,omitempty"`
	Organization     string `json:"organization,omitempty"`
	OrganizationUnit string `json:"organization_unit,omitempty"`
	Locality         string `json:"locality,omitempty"`
	State            string `json:"state,omitempty"`
	Country          string `json:"country,omitempty"`
	Duration         int    `json:"duration,omitempty"`
	CA               string `json:"ca,omitempty"`
	IsCA             bool   `json:"is_ca,omitempty"`
	SelfSign         bool   `json:"self_sign,omitempty"`
	SSHComment       string `json:"ssh_comment,omitempty"`
}

/*
  generate a credential for CredHub
*/
func GenerateCredentials(w http.ResponseWriter, r *http.Request) {
	session := GetSession(w, r, cookieName)
	muxvars := mux.Vars(r)
	credType := muxvars["credtype"]
	accessToken := session.Values["access_token"].(string)
	if r.Method == http.MethodPost {
		switch credType {
		case "password":
			credName := r.FormValue("name")
			r.ParseForm()
			//get checkbox values
			excludeUpper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"], ""))
			excludeLower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"], ""))
			excludeNumber, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"], ""))
			includeSpecial, _ := strconv.ParseBool(strings.Join(r.Form["include_special"], ""))
			credLength, _ := strconv.Atoi(strings.Join(r.Form["length"], ""))
			//add to struct
			params := PasswordParameters{
				ExcludeUpper:   excludeUpper,
				ExcludeLower:   excludeLower,
				ExcludeNumber:  excludeNumber,
				IncludeSpecial: includeSpecial,
				Length:         credLength,
			}
			//create payload
			passw := PasswordStruct{
				Name:       credName,
				Type:       "password",
				Parameters: params,
			}
			PostCredentials(w, r, passw, accessToken)
		case "user":
			credName := r.FormValue("name")
			r.ParseForm()
			//get checkbox values
			excludeUpper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"], ""))
			excludeLower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"], ""))
			excludeNumber, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"], ""))
			includeSpecial, _ := strconv.ParseBool(strings.Join(r.Form["include_special"], ""))
			credLength, _ := strconv.Atoi(strings.Join(r.Form["length"], ""))
			credUsername := strings.Join(r.Form["username"], "")
			//add to struct
			params := PasswordParameters{
				ExcludeUpper:   excludeUpper,
				ExcludeLower:   excludeLower,
				ExcludeNumber:  excludeNumber,
				IncludeSpecial: includeSpecial,
				Length:         credLength,
				Username:       credUsername,
			}
			//create payload
			passw := PasswordStruct{
				Name:       credName,
				Type:       "user",
				Parameters: params,
			}
			PostCredentials(w, r, passw, accessToken)
		case "certificate":
			credName := r.FormValue("name")
			r.ParseForm()
			//get checkbox values
			isCa, _ := strconv.ParseBool(strings.Join(r.Form["is_ca"], ""))
			selfSign, _ := strconv.ParseBool(strings.Join(r.Form["self_sign"], ""))
			organization := strings.Join(r.Form["organization"], "")
			organizationUnit := strings.Join(r.Form["organization_unit"], "")
			commonName := strings.Join(r.Form["common_name"], "")
			alternativeNames := strings.Join(r.Form["alternative_names"], "")
			locality := strings.Join(r.Form["locality"], "")
			state := strings.Join(r.Form["state"], "")
			country := strings.Join(r.Form["country"], "")
			ca := strings.Join(r.Form["ca"], "")
			duration, _ := strconv.Atoi(strings.Join(r.Form["duration"], ""))
			//add to struct
			params := PasswordParameters{
				IsCA:             isCa,
				SelfSign:         selfSign,
				Organization:     organization,
				OrganizationUnit: organizationUnit,
				CommonName:       commonName,
				AlternativeNames: alternativeNames,
				Locality:         locality,
				State:            state,
				Country:          country,
				CA:               ca,
				Duration:         duration,
			}
			//create payload
			passw := PasswordStruct{
				Name:       credName,
				Type:       "certificate",
				Parameters: params,
			}
			PostCredentials(w, r, passw, accessToken)
		case "rsa":
			credName := r.FormValue("name")
			r.ParseForm()
			//add to struct
			params := PasswordParameters{}
			//create payload
			passw := PasswordStruct{
				Name:       credName,
				Type:       "rsa",
				Parameters: params,
			}
			PostCredentials(w, r, passw, accessToken)
		case "ssh":
			credName := r.FormValue("name")
			r.ParseForm()
			sshComment := strings.Join(r.Form["ssh_comment"], "")
			//add to struct
			params := PasswordParameters{
				SSHComment: sshComment,
			}
			//create payload
			passw := PasswordStruct{
				Name:       credName,
				Type:       "ssh",
				Parameters: params,
			}
			PostCredentials(w, r, passw, accessToken)
		default:
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		if stringInSlice(credType, []string{"password", "user", "certificate", "rsa", "ssh"}) {
			tmpl := template.Must(template.ParseFiles("templates/generate/" + credType + ".html"))
			tmpl.ExecuteTemplate(w, "base", nil)
		} else {
			ReturnBlank(w)
		}
	}
	return
}

/*
  function to actually post it into CredHub
*/
func PostCredentials(w http.ResponseWriter, r *http.Request, credential interface{}, accessToken string) {
	apiQuery := "/api/v1/data"
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	jsonStr, _ := json.Marshal(credential)
	req, _ := http.NewRequest("POST", credhubServer+apiQuery, bytes.NewBuffer(jsonStr))
	req.Header.Add("authorization", "bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, reqErr := netClient.Do(req)
	if reqErr != nil {
		fmt.Println(reqErr)
		http.Error(w, "Error", http.StatusBadRequest)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	flashMessage := []byte(body)
	CheckError(w, r, flashMessage, "Successfully generated credential", "success")
	defer resp.Body.Close()
}
