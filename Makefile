run: build
	@./bin/httpServer

debug: build
	@dlv exec ./bin/httpServer --headless --listen=:2345 --api-version=2 --log

build: 
	@cd src && go build -o ../bin/httpServer ./main.go
	@sudo setcap cap_net_raw+ep bin/httpServer

test: 
	@cd src && go test ./...

