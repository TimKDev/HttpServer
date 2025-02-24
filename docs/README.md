## Setup
Set permissions for the executable to open raw sockets: 
`sudo setcap cap_net_raw+ep /bin/httpServer.exe`

Another problem is that the kernel will always try to handle the Tcp layer and thus stop any connection by sending a RST. A possible solution is to add a rule to the iptable to prevent sending RST:
`sudo iptables -A OUTPUT -p tcp --sport 10000 --tcp-flags RST RST -j DROP`

This rule can again be removed using:
`sudo iptables -D OUTPUT -p tcp --sport 10000 --tcp-flags RST RST -j DROP`

## Debugging in VSCode
Install the Go Debugger Delve `go install github.com/go-delve/delve/cmd/dlv@latest`.