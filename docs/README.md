# Custom HTTP Server Implementation

A low-level HTTP server implementation in Go that handles TCP/IP protocols directly using raw sockets. This is a learning project to teach myself the basics of networking.

## Features

- **Custom TCP/IP Stack**: Partial implementation of TCP and IP packet handling
- **Raw Socket Programming**: Direct network interface communication
- **HTTP Protocol Support**: Parser and handler for HTTP/1.1 requests
- **TCP Connection Management**: Full TCP connection lifecycle handling including:
  - Three-way handshake
  - Packet sequencing
  - Connection termination
- **IP Fragmentation**: Support for handling fragmented IP packets
- **Checksum Verification**: TCP and IP checksum calculation and verification

## Technical Highlights

- Written in Go 1.23.4
- Zero dependencies on standard networking libraries
- Implements network protocols from scratch

## Prerequisites

- Linux operating system
- Go 1.23.4 or higher
- Root privileges (for raw socket operations)
- Delve debugger (for debugging)

## Installation

1. Clone the repository
2. Navigate to the project directory
3. Build the project: `make`

## Explaination Makefile 
Set permissions for the executable to open raw sockets: 
`sudo setcap cap_net_raw+ep /bin/httpServer.exe`

Another problem is that the kernel will always try to handle the Tcp layer and thus stop any connection by sending a RST. A possible solution is to add a rule to the iptable to prevent sending RST:
`sudo iptables -A OUTPUT -p tcp --sport 10000 --tcp-flags RST RST -j DROP`

This rule can again be removed using:
`sudo iptables -D OUTPUT -p tcp --sport 10000 --tcp-flags RST RST -j DROP`

## Development

For debugging, the project includes VSCode configurations and supports the Delve debugger. Install the Go Debugger Delve `go install github.com/go-delve/delve/cmd/dlv@latest`.

To start a debug session:

1. Run `make debug`
2. Attach VSCode using the provided launch configuration
3. Set breakpoints and debug as needed