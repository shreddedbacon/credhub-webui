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
  //"strings"
)


type GetCredential struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
	} `json:"data"`
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

type GetCredentialJson struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            interface{} `json:"value"`
	} `json:"data"`
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

type GetCredentialPageData struct {
	PageTitle string
	Credentials     []GetCredentialData
}

type GetCredentialPageDataSSH struct {
	PageTitle string
	Credentials     []GetCredentialSSH
}

type GetCredentialPageDataJson struct {
	PageTitle string
	Credentials     []GetCredentialJson
	JSONData     interface{}
	JSONData2     string
}
/*
type GetCredentialData struct {
	Data []struct {
		Type             string    `json:"type"`
		VersionCreatedAt time.Time `json:"version_created_at"`
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Value            struct {
			PublicKey    string `json:"public_key"`
			PrivateKey   string `json:"private_key"`
      PublicKeyFingerprint string `json:"public_key_fingerprint"`
			Username     string `json:"username"`
			Password     string `json:"password"`
			Ca           string `json:"ca"`
			Certificate  string `json:"certificate"`
			PasswordHash string `json:"password_hash"`
		} `json:"value"`
	} `json:"data"`
}*/
func GetCredentials(w http.ResponseWriter, r *http.Request) {
  session, _ := store.Get(r, cookie_name)
  // api call to make
  api_query := "/api/v1/data?name="
  //if we get a search query, add it to the api_query
  param1, ok := r.URL.Query()["name"]
  if ok {
    api_query = api_query+param1[0]
  }

  // use template

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
      data2 := GetCredentialPageDataSSH{
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialSSH{
          credRespSSH,
        },
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_rsa.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data2)
      return
    case "ssh":
    	credRespSSH := GetCredentialSSH{}
      if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespSSH); credServErr != nil {
        fmt.Println(credServErr)
      }
      data2 := GetCredentialPageDataSSH{
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialSSH{
          credRespSSH,
        },
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential_ssh.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data2)
      return
    case "certificate":
    	credRespdata := GetCredentialData{}
      if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespdata); credServErr != nil {
        fmt.Println(credServErr)
      }
      data := GetCredentialPageData{
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialData{
          credRespdata,
        },
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data)
      return
    case "user":
    	credRespdata := GetCredentialData{}
      if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespdata); credServErr != nil {
        fmt.Println(credServErr)
      }
      data := GetCredentialPageData{
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialData{
          credRespdata,
        },
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data)
      return
    case "json":

    	credRespJson := GetCredentialJson{}
      if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespJson); credServErr != nil {
        fmt.Println(credServErr)
      }
      JSONDataBytes := []byte("")
      var f interface{}
      for _, cred := range credRespJson.Data {
        JSONDataBytes, _ = json.Marshal(cred.Value)
        if err := json.Unmarshal(JSONDataBytes, &f); err != nil {
      		panic(err)
      	}
        //fmt.Println(string(JSONDataBytes))
      }
      JSONDataString, _ := json.MarshalIndent(f, "", "  ")
      JSONDataString2 := string(JSONDataString)
      data3 := GetCredentialPageDataJson{
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialJson{
          credRespJson,
        },
        JSONData: f,
        JSONData2: JSONDataString2,
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
    		PageTitle: "Get Credential",
    		Credentials: []GetCredentialData{
          credRespdata,
        },
    	}
      tmpl := template.Must(template.ParseFiles("templates/get_credential.html", "templates/base.html"))
    	tmpl.ExecuteTemplate(w, "base", data)
      return
    }
  }
  credRespdata := GetCredentialData{}
  if credServErr := json.Unmarshal([]byte(credRespBytes), &credRespdata); credServErr != nil {
    fmt.Println(credServErr)
  }
  data := GetCredentialPageData{
    PageTitle: "Get Credential",
    Credentials: []GetCredentialData{
      credRespdata,
    },
  }
  tmpl := template.Must(template.ParseFiles("templates/get_credential.html", "templates/base.html"))
	tmpl.ExecuteTemplate(w, "base", data)
  return
}
