# CredHub Web Interface

A web interface for performing basic functions with CredHub.

## Log in
You need to log in with valid Credentials
Currently supports:
* `client_id`
* `client_secret`

## Features
Currently supports:
* View
* Delete
* Generate
* Search

# Screenshots
Sign in
![sign in](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/01-sign_in.png)
List all credentials in CredHub
![list creds](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/02-list_creds.png)
Search credentials by using a search term, it uses `name-like` from CredHub
![search creds](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/03-search-creds.png)
View a selected credential
![view cred](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/04-view_cred.png)
Generate a credential
![generate cred](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/05-generate_cred.png)
View a generated credential
![view generated](https://github.com/shreddedbacon/credhub-webui/blob/master/screenshots/06-view_generated.png)

# Build
```
docker build -t shreddedbacon/credhub-webui .
```
# Run
```
docker run -p 8443:8443 -e CREDHUB_SERVER=https://<ip>:<port> shreddedbacon/credhub-webui
```
E.g
```
docker run -p 8443:8443 -e CREDHUB_SERVER=https://192.168.50.6:8844 shreddedbacon/credhub-webui
```

# Access

```
https://localhost:8443
```
