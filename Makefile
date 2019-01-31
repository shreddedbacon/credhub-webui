URL := $(shell cat .envvars | grep "URL=" | grep -oP "http.*")

build:
	docker-compose build

run:
	docker-compose up -d

open:
	@if [ xdg-open ];	then \
    xdg-open $(URL); \
	else \
		open $(URL); \
  fi

build-docker:
	docker build -t shreddedbacon/credhub-webui .

docker-push:
	docker push shreddedbacon/credhub-webui
