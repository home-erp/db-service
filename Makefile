VERSION ?= latest

build:
	go build


it: build db
	cd it && go test

db: 
	cd database; docker build -t home-erp/database:${VERSION} .

docker: build
	docker build -t home-erp/db-service:${VERSION} .
