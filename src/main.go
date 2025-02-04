package main

import (
	"fmt"
	"http-server/ip-parser"
	"log"
	"syscall"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Socket creation error: %v", err)
	}
	defer syscall.Close(fd)

	fmt.Println("\nSocket created successfully")
	fmt.Println("Waiting for TCP packets... (Press Ctrl+C to stop)")

	for {
		buf := make([]byte, 65536)

		n, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println("Some Error happend")
			if err == syscall.EINTR {
				continue
			}
			log.Printf("Error receiving: %v", err)
			continue
		}

		if n <= 0 {
			continue
		}

		process(buf[:n], addr)

	}
}

func process(buffer []byte, addr syscall.Sockaddr) {
	fmt.Println("Recived Package")
	ipPaket, err := ipparser.ParseIPPaket(buffer)
	if err != nil {
		log.Printf("Ip parsing error: %v\n", err)
	}
	ipparser.Print(ipPaket)
}
