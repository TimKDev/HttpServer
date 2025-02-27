DLV_PATH := $(shell which dlv)
SERVER_PORT := 10000

run: build
	@./bin/httpServer

debug: build
	@sudo $(DLV_PATH) exec ./bin/httpServer --headless --listen=:2345 --api-version=2 --log

setup: 
	@sudo iptables -A OUTPUT -p tcp --sport $(SERVER_PORT) --tcp-flags RST RST -j DROP

cleanup:
	@sudo iptables -D OUTPUT -p tcp --sport $(SERVER_PORT) --tcp-flags RST RST -j DROP

build: 
	@cd src && go build -o ../bin/httpServer ./main.go
	@sudo setcap cap_net_raw+ep bin/httpServer

test: 
	@cd src && go test ./...

