package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"encoding/json"
  "time"
  "bytes"
)


type GetCredential struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
	} `json:"data"`
}

type GetCredentialPageData struct {
	PageTitle string
	Credentials     []GetCredentialData
}
type GetCredentialData struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            string `json:"value"`
	} `json:"data"`
}


type GetCredentialPageDataJson struct {
	PageTitle string
	Credentials     []GetCredentialJson
}

type GetCredentialJson struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            map[string]interface{} `json:"value"`
	} `json:"data"`
}

type GetCredentialPageDataSSH struct {
	PageTitle string
	Credentials     []GetCredentialSSH
}

type GetCredentialSSH struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            struct {
			PublicKey    string `json:"public_key"`
			PrivateKey   string `json:"private_key"`
      PublicKeyFingerprint string `json:"public_key_fingerprint"`
		} `json:"value"`
	} `json:"data"`
}

type GetCredentialPageDataUser struct {
	PageTitle string
	Credentials     []GetCredentialUser
}

type GetCredentialUser struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            struct {
			UserName    string `json:"username"`
			PassWord   string `json:"password"`
      PassWordHash string `json:"password_hash"`
		} `json:"value"`
	} `json:"data"`
}

type GetCredentialPageDataCert struct {
	PageTitle string
	Credentials     []GetCredentialCert
}

type GetCredentialCert struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            struct {
			CA    string `json:"ca"`
			Certificate   string `json:"certificate"`
      PrivateKey string `json:"private_key"`
		} `json:"value"`
	} `json:"data"`
}


func GetCredentials(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
  // api call to make
  api_query := "/api/v1/data?name="
  //if we get a search query, add it to the api_query
  param1, ok := r.URL.Query()["name"]
  if ok {
    api_query = api_query+param1[0]
  }

	// Check if user is authenticated
  ValidateAuthSessionFalse(session, w, r)
  access_token := session.Values["access_token"].(string)

  //validate token
  ValidateAuthToken(session, access_token, w, r)

  // call the credhub api to get all credentials
  // set up netClient for use later
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now
	req, _ := http.NewRequest("GET", credhub_server+api_query, bytes.NewBuffer([]byte("")))
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
	credResp := GetCredential{}
  if credServErr := json.Unmarshal([]byte(credRespBytes), &credResp); credServErr != nil {
    fmt.Println(credServErr)
  }
  for _, cred := range credResp.Data {
    //fmt.Println(cred.Value)
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_rsa.html", "templates/base.html"))
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_ssh.html", "templates/base.html"))
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_certificate.html", "templates/base.html"))
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_user.html", "templates/base.html"))
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_json.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data3)
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
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data)
      return
    }
  }
  // go home if no conditions met
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
  return
}
