# CredHub Web Interface

A web interface for performing basic functions with CredHub, uses `client_id` and `client_secret` currently


# Build
```
docker build -t shreddedbacon/credhub-webui .
```
# Run
```
docker run -p 8080:8080 -e AUTH_SERVER=https://<ip>:<port> shreddedbacon/credhub-webui
```
E.g
```
docker run -p 8080:8080 -e AUTH_SERVER=https://192.168.50.6:8844 shreddedbacon/credhub-webui
```

# TODO
* Use HTTPS
