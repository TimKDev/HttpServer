run: build
	@./bin/httpServer

build: 
	@go build -o bin/httpServer
	sudo setcap cap_net_raw+ep bin/httpServer

test: 
	@go test ./...

