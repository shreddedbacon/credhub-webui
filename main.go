package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	Expiry      int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
	ClientID    string `json:"client_id"`
}

type AuthServerResponse struct {
	AuthServer struct {
		URL string `json:"url"`
	} `json:"auth-server"`
	App struct {
		Name string `json:"name"`
	} `json:"app"`
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	keyVal        = os.Getenv("COOKIE_KEY")
	key           = []byte(keyVal)
	store         = sessions.NewCookieStore(key)
	credhubServer = os.Getenv("CREDHUB_SERVER")
	uiSslCert     = os.Getenv("UI_SSL_CERT")
	uiSslKey      = os.Getenv("UI_SSL_KEY")
	cookieName    = os.Getenv("COOKIE_NAME")
	clientID      = os.Getenv("CLIENT_ID")
	clientSecret  = os.Getenv("CLIENT_SECRET")
	uiUrl         = os.Getenv("UI_URL") //used for callback url
)

type CredentialsData struct {
	Credentials []struct {
		VersionCreatedAt time.Time `json:"version_created_at"`
		Name             string    `json:"name"`
	} `json:"credentials"`
}

type CredentialPageData struct {
	PageTitle   string
	Credentials []CredentialsData
	UserName    string
	Flash       Flash
}

func ListCredentials(w http.ResponseWriter, r *http.Request) {
	//set the access token from session
	session := GetSession(w, r, cookieName)
	accessToken, _ := session.Values["access_token"].(string)

	//api call to make
	apiQuery := "/api/v1/data?name-like="
	//if we get a search query, add it to the api_query
	param1, ok := r.URL.Query()["search"]
	if ok {
		apiQuery = apiQuery + param1[0]
	}
	// call the credhub api to get all credentials
	// set up netClient for use later
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore cert for now FIX: add credhub and uaa certificate as environment variables on startup
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
	credResp := CredentialsData{}
	if credServErr := json.Unmarshal([]byte(credRespBytes), &credResp); credServErr != nil {
		fmt.Println(credServErr)
	}
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
	var p jwt.Parser
	claims := jwt.MapClaims{}
	_, _, _ = p.ParseUnverified(accessToken, claims)
	userNameVal := ""
	if val, ok := claims["user_name"]; ok {
		userNameVal = val.(string)
	} else {
		userNameVal = claims["client_id"].(string)
	}
	data := CredentialPageData{
		PageTitle: "List Credentials",
		Credentials: []CredentialsData{
			credResp,
		},
		UserName: userNameVal,
		Flash:    flash,
	}
	// use template
	tmpl := template.Must(template.ParseFiles("templates/credentials.html", "templates/base.html"))
	tmpl.ExecuteTemplate(w, "base", data)
}

func ReturnBlank(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "")
}

func RedirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RedirectLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "favicon.ico")
}

func GetSession(w http.ResponseWriter, r *http.Request, sessionCookie string) *sessions.Session {
	session, err := store.Get(r, sessionCookie)
	if err != nil {
		fmt.Printf("session error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	return session
}

func AddFlash(w http.ResponseWriter, r *http.Request, flashMessage string, flashType string) {
	flashsession := GetSession(w, r, "flash-cookie")
	flash := Flash{
		Type:    flashType,
		Message: flashMessage,
		Display: true,
	}
	flashsession.AddFlash(flash)
	flashsession.Save(r, w)
}

func CheckError(w http.ResponseWriter, r *http.Request, responseBody []byte, defaultFlashMessage string, defaultFlashType string) {
	var rawJson map[string]interface{}
	json.Unmarshal(responseBody, &rawJson)
	for a, b := range rawJson {
		if a == "error" {
			AddFlash(w, r, b.(string), "danger")
			return
		}
	}
	AddFlash(w, r, defaultFlashMessage, defaultFlashType)
	return
}

func ValidateToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		session := GetSession(w, req, cookieName)
		accessToken, setbool := session.Values["access_token"].(string)
		if setbool == true && accessToken == "" {
			RedirectLogin(w, req)
			//return
		} else if setbool == false {
			RedirectLogin(w, req)
		} else {
			var p jwt.Parser
			token, _, _ := p.ParseUnverified(accessToken, &jwt.StandardClaims{})
			if err := token.Claims.Valid(); err != nil {
				//invalid
				RedirectLogin(w, req)
				//return
			} else {
				//valid
				next(w, req)
				//return
			}
		}
		//RedirectLogin(w, r)
		return
	})
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func main() {
	keyValVar := flag.String("cookie-key", "", "Must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)")
	cookieNameVar := flag.String("cookie-name", "auth-cookie", "Name of the cookie to use (auth-cookie)")
	credhubServerVar := flag.String("credhub-server", "", "URL of CredHub server to target (https://<ip-or-host>:<port>)")
	uiSslCertVar := flag.String("ui-ssl-cert", "", "SSL certificate for the web frontend (server.crt)")
	uiSslKeyVar := flag.String("ui-ssl-key", "", "SSL certificate key for the web frontend (server.key)")
	clientIDVar := flag.String("client-id", "", "Client ID that has credhub.read and credhub.write authorization")
	clientSecretVar := flag.String("client-secret", "", "Secret for the Client ID")
	uiUrlVar := flag.String("ui-url", "", "URL of this UI (https://<ip-or-host>:<port>)")
	flag.Parse()
	if len(os.Getenv("CREDHUB_SERVER")) == 0 {
		if *credhubServerVar != "" {
			credhubServer = *credhubServerVar
		} else {
			log.Fatalln("CREDHUB_SERVER not set")
		}
	}
	if len(os.Getenv("COOKIE_NAME")) == 0 {
		if *cookieNameVar != "" {
			cookieName = *cookieNameVar
		} else {
			log.Fatalln("COOKIE_NAME not set")
		}
	}
	if len(os.Getenv("COOKIE_KEY")) == 0 {
		if *keyValVar != "" {
			keyVal = *keyValVar
			key = []byte(keyVal)
			store = sessions.NewCookieStore(key)
		} else {
			log.Fatalln("COOKIE_NAME not set")
		}
	}
	if len(os.Getenv("UI_SSL_CERT")) == 0 {
		if *uiSslCertVar != "" {
			uiSslCert = *uiSslCertVar
		} else {
			log.Fatalln("UI_SSL_CERT not set")
		}
	}
	if len(os.Getenv("UI_SSL_KEY")) == 0 {
		if *uiSslKeyVar != "" {
			uiSslKey = *uiSslKeyVar
		} else {
			log.Fatalln("UI_SSL_KEY not set")
		}
	}
	if len(os.Getenv("CLIENT_ID")) == 0 {
		if *clientIDVar != "" {
			clientID = *clientIDVar
		} else {
			log.Fatalln("CLIENT_ID not set")
		}
	}
	if len(os.Getenv("CLIENT_SECRET")) == 0 {
		if *clientSecretVar != "" {
			clientSecret = *clientSecretVar
		} else {
			clientSecret = "" //allow empty secret?
			//log.Fatalln("CLIENT_SECRET not set")
		}
	}
	if len(os.Getenv("UI_URL")) == 0 {
		if *uiUrlVar != "" {
			uiUrl = *uiUrlVar
		} else {
			log.Fatalln("UI_URL not set")
		}
	}

	gob.Register(Flash{})
	log.SetFlags(log.Ldate | log.Ltime)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
	}
	r := mux.NewRouter()
	r.HandleFunc("/login", Login)
	r.HandleFunc("/login/callback", LoginCallback)
	r.HandleFunc("/logout", Logout)
	r.HandleFunc("/get", ValidateToken(GetCredentials))
	r.HandleFunc("/delete", ValidateToken(DeleteCredentials))
	r.HandleFunc("/generate/{credtype}", ValidateToken(GenerateCredentials))
	r.HandleFunc("/set/{credtype}", ValidateToken(SetCredentials))
	r.HandleFunc("/favicon.ico", FaviconHandler)
	r.HandleFunc("/", ValidateToken(ListCredentials))

	err := http.ListenAndServeTLS(":8443", uiSslCert, uiSslKey, LogRequest(r))
	if err != nil {
		fmt.Println(err)
	}
}

func LogRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
