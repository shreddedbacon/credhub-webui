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
  //"io/ioutil"
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
  session, _ := store.Get(r, cookie_name)
  muxvars := mux.Vars(r)
  credtype := muxvars["credtype"]

	// Check if user is authenticated
  ValidateAuthSessionFalse(session, w, r)
  access_token := session.Values["access_token"].(string)

  //validate token
  ValidateAuthToken(session, access_token, w, r)

	if r.Method == http.MethodPost {
    switch credtype {
    case "pass":
      cred_name := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      exclude_upper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"],""))
      exclude_lower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"],""))
      exclude_number, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"],""))
      include_special, _ := strconv.ParseBool(strings.Join(r.Form["include_special"],""))
      cred_length, _ := strconv.Atoi(strings.Join(r.Form["length"],""))
      //add to struct
      params := PasswordParameters{
        ExcludeUpper: exclude_upper,
        ExcludeLower: exclude_lower,
        ExcludeNumber: exclude_number,
        IncludeSpecial: include_special,
        Length: cred_length,
      }
      //create payload
      passw := PasswordStruct{
        Name: cred_name,
        Type: "password",
        Parameters: params,
      }
      PostCredentials(w, passw, access_token)
    case "user":
      cred_name := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      exclude_upper, _ := strconv.ParseBool(strings.Join(r.Form["exclude_upper"],""))
      exclude_lower, _ := strconv.ParseBool(strings.Join(r.Form["exclude_lower"],""))
      exclude_number, _ := strconv.ParseBool(strings.Join(r.Form["exclude_number"],""))
      include_special, _ := strconv.ParseBool(strings.Join(r.Form["include_special"],""))
      cred_length, _ := strconv.Atoi(strings.Join(r.Form["length"],""))
      cred_username := strings.Join(r.Form["username"],"")
      //add to struct
      params := PasswordParameters{
        ExcludeUpper: exclude_upper,
        ExcludeLower: exclude_lower,
        ExcludeNumber: exclude_number,
        IncludeSpecial: include_special,
        Length: cred_length,
        Username: cred_username,
      }
      //create payload
      passw := PasswordStruct{
        Name: cred_name,
        Type: "user",
        Parameters: params,
      }
      PostCredentials(w, passw, access_token)
    case "certificate":
      cred_name := r.FormValue("name")
      r.ParseForm()
      //get checkbox values
      is_ca, _ := strconv.ParseBool(strings.Join(r.Form["is_ca"],""))
      self_sign, _ := strconv.ParseBool(strings.Join(r.Form["self_sign"],""))
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
        IsCA: is_ca,
        SelfSign: self_sign,
        Organization: organization,
        OrganizationUnit: organization_unit,
        CommonName: common_name,
        AlternativeNames: alternative_names,
        Locality: locality,
        State: state,
        Country: country,
        CA: ca,
        Duration: duration,
      }
      //create payload
      passw := PasswordStruct{
        Name: cred_name,
        Type: "certificate",
        Parameters: params,
      }
      PostCredentials(w, passw, access_token)
    case "rsa":
      cred_name := r.FormValue("name")
      r.ParseForm()
      //add to struct
      params := PasswordParameters{}
      //create payload
      passw := PasswordStruct{
        Name: cred_name,
        Type: "rsa",
        Parameters: params,
      }
      PostCredentials(w, passw, access_token)
    case "ssh":
      cred_name := r.FormValue("name")
      r.ParseForm()
      ssh_comment := strings.Join(r.Form["ssh_comment"],"")
      //add to struct
      params := PasswordParameters{
        SSHComment: ssh_comment,
      }
      //create payload
      passw := PasswordStruct{
        Name: cred_name,
        Type: "ssh",
        Parameters: params,
      }
      PostCredentials(w, passw, access_token)
    default:
      RedirectHome(w)
      return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
    return
	} else {
    if stringInSlice(credtype, []string{"password", "user", "certificate", "rsa", "ssh"}) {
      tmpl := template.Must(template.ParseFiles("templates/generate/"+credtype+".html"))
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

func PostCredentials(w http.ResponseWriter, credential PasswordStruct, access_token string) {
  api_query := "/api/v1/data"
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
  jsonStr, _ := json.Marshal(credential)
  req, _ := http.NewRequest("POST", credhub_server+api_query, bytes.NewBuffer(jsonStr))
  req.Header.Add("authorization", "bearer "+access_token)
  req.Header.Set("Content-Type", "application/json")
  resp, reqErr := netClient.Do(req)
  if reqErr != nil {
    fmt.Println(reqErr)
    http.Error(w, "Error", http.StatusBadRequest)
    return
  }
  defer resp.Body.Close()
}
