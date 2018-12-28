#!/bin/sh
set -e -u -x
# Install git for go get

echo ">> Install git"
apk add --no-cache git

# set up directory stuff for golang
echo ">> Setup Directories"
mkdir -p /go/src/github.com/shreddedbacon/
ln -s $PWD/credhub-webui-release /go/src/github.com/shreddedbacon/credhub-webui
ls -alh /go/src/github.com/shreddedbacon
cd  /go/src/github.com/shreddedbacon/credhub-webui
echo ">> Get"
go get -v .
cd -
echo ">> Build"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o built-release/credhub-webui github.com/shreddedbacon/credhub-webui

echo ">> Create artifact"
VERSION=$(cat ${VERSION_FROM})
cd built-release
tar czf credhub-webui-linux-$VERSION.tar.gz credhub-webui
