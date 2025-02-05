run: build
	@./bin/httpServer

build: 
	@cd src && go build -o ../bin/httpServer ./main.go
	@sudo setcap cap_net_raw+ep bin/httpServer

test: 
	@cd src && go test ./...

