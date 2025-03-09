DLV_PATH := $(shell which dlv)
SERVER_PORT := 10000

run: build setup 
	@./bin/httpServer

debug: build setup
	@sudo $(DLV_PATH) exec ./bin/httpServer --headless --listen=:2345 --api-version=2 --log

setup: cleanup
	@sudo iptables -A OUTPUT -p tcp --sport $(SERVER_PORT) --tcp-flags RST RST -j DROP

cleanup:
	@sudo iptables -D OUTPUT -p tcp --sport $(SERVER_PORT) --tcp-flags RST RST -j DROP 2>/dev/null || true

build: 
	@cd src && go build -o ../bin/httpServer ./main.go
	@sudo setcap cap_net_raw+ep bin/httpServer

test: 
	@cd src && go test ./...

