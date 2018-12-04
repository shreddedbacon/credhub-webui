package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
  "time"
  "bytes"
)

func DeleteCredentials(w http.ResponseWriter, r *http.Request) {
  session := GetSession(w, r)
  // api call to make
  apiQuery := "/api/v1/data?name="
  //if we get a search query, add it to the api_query
  param1, ok := r.URL.Query()["name"]
  if ok {
    apiQuery = apiQuery+param1[0]
  }
  accessToken := session.Values["access_token"].(string)
  // call the credhub api to get all credentials
  // set up netClient for use later
  var netClient = &http.Client{
    Timeout: time.Second * 10,
  }
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
	req, _ := http.NewRequest("DELETE", credhubServer+apiQuery, bytes.NewBuffer([]byte("")))
	req.Header.Add("authorization", "bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, reqErr := netClient.Do(req)
  if reqErr != nil {
    fmt.Println(reqErr)
  	http.Error(w, "Error", http.StatusBadRequest)
  	return
  }
	defer resp.Body.Close()
	/*body, _ := ioutil.ReadAll(resp.Body)
	credRespBytes := []byte(body)
  fmt.Println(string(credRespBytes))*/
  // go home if no conditions met
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  fmt.Fprint(w, "<meta http-equiv=\"refresh\" content=\"0;URL='/'\" />")
  return
}
