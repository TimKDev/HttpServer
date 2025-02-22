## Setup
Set permissions for the executable to open raw sockets: `sudo setcap cap_net_raw+ep /bin/httpServer.exe`

## Debugging in VSCode
Install the Go Debugger Delve `go install github.com/go-delve/delve/cmd/dlv@latest`.