FROM golang AS builder
RUN go version
COPY *.go /go/src/github.com/shreddedbacon/credhub-webui/
WORKDIR /go/src/github.com/shreddedbacon/credhub-webui/
RUN set -x && \
    go get -v .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o credhub-webui .

# actual container
FROM alpine:3.7
RUN apk --no-cache add ca-certificates openssl
WORKDIR /app/
# generate self signed for testing
RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"  -keyout server.key  -out server.crt
# bring the actual executable from the builder
COPY --from=builder /go/src/github.com/shreddedbacon/credhub-webui/credhub-webui .
# copy templates in
COPY templates/ templates
# blank favicon for now
RUN touch favicon.ico
EXPOSE 8443
# which certificate to use for the UI
ENV UI_SSL_CERT=server.crt
ENV UI_SSL_KEY=server.key
ENV COOKIE_KEY="super-secret-key"
ENV COOKIE_NAME="auth-cookie"
ENV UI_PORT="8443"
ENTRYPOINT ["./credhub-webui"]
