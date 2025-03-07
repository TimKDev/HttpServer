package main

import (
	receiverworker "http-server/receiver-worker"
	senderworker "http-server/sender-worker"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type ServerConfig struct {
}

func main() {
	socket := createRawSocket()
	defer syscall.Close(socket)
	go senderworker.Start()
	go receiverworker.Start(socket)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func createRawSocket() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Raw socket creation error: %v", err)
	}

	//This socket option tells the kernel that this application will create its own IP Headers
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	log.Println("\nSocket created successfully")
	return fd
}
