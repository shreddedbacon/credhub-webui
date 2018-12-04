package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"net/http"
  "time"
  "bytes"
  "strconv"
  "strings"
  "encoding/json"
  "github.com/gorilla/mux"
)

type PasswordStruct struct {
  Name             string    `json:"name"`
	Type             string    `json:"type"`
  Parameters PasswordParameters `json:"parameters"`
}

type PasswordParameters struct {
	ExcludeUpper    bool `json:"exclude_upper,omitempty"`
	ExcludeLower    bool `json:"exclude_lower,omitempty"`
	ExcludeNumber   bool `json:"exclude_number,omitempty"`
	IncludeSpecial  bool `json:"include_special,omitempty"`
  Username  string `json:"username,omitempty"`
  Length int `json:"length,omitempty"`
  CommonName string `json:"common_name,omitempty"`
  AlternativeNames string `json:"alternative_names,omitempty"`
  Organization string `json:"organization,omitempty"`
  OrganizationUnit string `json:"organization_unit,omitempty"`
  Locality string `json:"locality,omitempty"`
  State string `json:"state,omitempty"`
  Country string `json:"country,omitempty"`
  Duration int `json:"duration,omitempty"`
  CA string `json:"ca,omitempty"`
  IsCA bool `json:"is_ca,omitempty"`
  SelfSign bool `json:"self_sign,omitempty"`
  SSHComment string `json:"ssh_comment,omitempty"`
}

func GenerateCredentials(w http.ResponseWriter, r *http.Request) {
  session := GetSession(w, r)
  muxvars := mux.Vars(r)
  credType := muxvars["credtype"]
  accessToken := session.Values["access_token"].(string)
	if r.Method == http.MethodPost {
    switch credType {
    case "pass":
      credName := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      excludeUpper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"],""))
      excludeLower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"],""))
      excludeNumber, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"],""))
      includeSpecial, _ := strconv.ParseBool(strings.Join(r.Form["include_special"],""))
      credLength, _ := strconv.Atoi(strings.Join(r.Form["length"],""))
      //add to struct
      params := PasswordParameters{
        ExcludeUpper: excludeUpper,
        ExcludeLower: excludeLower,
        ExcludeNumber: excludeNumber,
        IncludeSpecial: includeSpecial,
        Length: credLength,
      }
      //create payload
      passw := PasswordStruct{
        Name: credName,
        Type: "password",
        Parameters: params,
      }
      PostCredentials(w, passw, accessToken)
    case "user":
      credName := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      excludeUpper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"],""))
      excludeLower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"],""))
      excludeNumber, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"],""))
      includeSpecial, _ := strconv.ParseBool(strings.Join(r.Form["include_special"],""))
      credLength, _ := strconv.Atoi(strings.Join(r.Form["length"],""))
      credUsername := strings.Join(r.Form["username"],"")
      //add to struct
      params := PasswordParameters{
        ExcludeUpper: excludeUpper,
        ExcludeLower: excludeLower,
        ExcludeNumber: excludeNumber,
        IncludeSpecial: includeSpecial,
        Length: credLength,
        Username: credUsername,
      }
      //create payload
      passw := PasswordStruct{
        Name: credName,
        Type: "user",
        Parameters: params,
      }
      PostCredentials(w, passw, accessToken)
    case "certificate":
      credName := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      isCa, _ := strconv.ParseBool(strings.Join(r.Form["is_ca"],""))
      selfSign, _ := strconv.ParseBool(strings.Join(r.Form["self_sign"],""))
      organization := strings.Join(r.Form["organization"],"")
      organization_unit := strings.Join(r.Form["organization_unit"],"")
      common_name := strings.Join(r.Form["common_name"],"")
      alternative_names := strings.Join(r.Form["alternative_names"],"")
      locality := strings.Join(r.Form["locality"],"")
      state := strings.Join(r.Form["state"],"")
      country := strings.Join(r.Form["country"],"")
      ca := strings.Join(r.Form["ca"],"")
      duration, _ := strconv.Atoi(strings.Join(r.Form["duration"],""))
      //add to struct
      params := PasswordParameters{
        IsCA: isCa,
        SelfSign: selfSign,
        Organization: organization,
        OrganizationUnit: organizationUnit,
        CommonName: commonName,
        AlternativeNames: alternativeNames,
        Locality: locality,
        State: state,
        Country: country,
        CA: ca,
        Duration: duration,
      }
      //create payload
      passw := PasswordStruct{
        Name: credName,
        Type: "certificate",
        Parameters: params,
      }
      PostCredentials(w, passw, accessToken)
    case "rsa":
      credName := r.FormValue("name")
      r.ParseForm()
      //add to struct
      params := PasswordParameters{}
      //create payload
      passw := PasswordStruct{
        Name: credName,
        Type: "rsa",
        Parameters: params,
      }
      PostCredentials(w, passw, accessToken)
    case "ssh":
      credName := r.FormValue("name")
      r.ParseForm()
      ssh_comment := strings.Join(r.Form["ssh_comment"],"")
      //add to struct
      params := PasswordParameters{
        SSHComment: sshComment,
      }
      //create payload
      passw := PasswordStruct{
        Name: credName,
        Type: "ssh",
        Parameters: params,
      }
      PostCredentials(w, passw, accessToken)
    default:
      RedirectHome(w)
      return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
    return
	} else {
    if stringInSlice(credType, []string{"password", "user", "certificate", "rsa", "ssh"}) {
      tmpl := template.Must(template.ParseFiles("templates/generate/"+credType+".html"))
      tmpl.ExecuteTemplate(w, "base", nil)
      return
    } else {
      ReturnBlank(w)
      return
    }
  }
  ReturnBlank(w)
  return
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func PostCredentials(w http.ResponseWriter, credential PasswordStruct, accessToken string) {
  api_query := "/api/v1/data"
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
  jsonStr, _ := json.Marshal(credential)
  req, _ := http.NewRequest("POST", credhub_server+api_query, bytes.NewBuffer(jsonStr))
  req.Header.Add("authorization", "bearer "+accessToken)
  req.Header.Set("Content-Type", "application/json")
  resp, reqErr := netClient.Do(req)
  if reqErr != nil {
    fmt.Println(reqErr)
    http.Error(w, "Error", http.StatusBadRequest)
    return
  }
  defer resp.Body.Close()
}
