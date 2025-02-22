package main

import (
	"fmt"
	"http-server/ip-handler"
	"http-server/ip-parser"
	"log"
	"syscall"
)

type ServerConfig struct {
}

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
		n, _, err := syscall.Recvfrom(fd, buf, 0)

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

		go process(buf[:n], fd)
	}
}

func process(buffer []byte, fd int) {
	ipPaket, err := ipparser.ParseIPPaket(buffer)
	if err != nil {
		log.Printf("Ip parsing error: %v\n", err)
	}
	ipPaketsToSend, err := iphandler.HandleIPPackage(ipPaket)
	if err != nil {
		log.Fatal("Ip handeling failed")
	}
	if ipPaketsToSend == nil {
		return
	}
	fmt.Println("Request IP Pakete:")
	ipparser.Print(ipPaket)
	for _, packageToSend := range ipPaketsToSend.PackagesToSend {
		addr := syscall.SockaddrInet4{
			Port: int(ipPaketsToSend.DestinationPort),
			Addr: ipPaket.DestinationIP,
		}
		err := syscall.Sendto(fd, packageToSend, 0, &addr)
		if err != nil {
			log.Printf("Error sending packet: %v", err)
		}
	}

}
