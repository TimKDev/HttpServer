package main

import (
	"fmt"
	iphandler "http-server/ip-handler"
	ipparser "http-server/ip-parser"
	"log"
	"os"
	"syscall"
)

type ServerConfig struct {
}

func main() {
	socket := createRawSocket()
}

func createRawSocket() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Raw socket creation error: %v", err)
	}
	defer syscall.Close(fd)

	//This socket option tells the kernel that this application will create its own IP Headers
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	log.Println("\nSocket created successfully")
	return fd
}
