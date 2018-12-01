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
* Search

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
