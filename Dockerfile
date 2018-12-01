FROM golang AS builder
RUN go version

COPY *.go /go/src/github.com/sb/goweb/
WORKDIR /go/src/github.com/sb/goweb/
RUN set -x && \
    go get -v .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o app .

# Stage 2 (to create a downsized "container executable", ~7MB)
# If you need SSL certificates for HTTPS, replace `FROM SCRATCH` with:
#
FROM alpine:3.7
RUN apk --no-cache add ca-certificates openssl
WORKDIR /root/
RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"  -keyout server.key  -out server.crt
COPY --from=builder /go/src/github.com/sb/goweb/app .
COPY *.html ./
RUN touch favicon.ico

EXPOSE 8443
ENTRYPOINT ["./app"]
