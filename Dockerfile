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
RUN apk --no-cache add ca-certificates
#FROM scratch
WORKDIR /root/
COPY --from=builder /go/src/github.com/sb/goweb/app .
COPY login.html .

EXPOSE 80
ENTRYPOINT ["./app"]
