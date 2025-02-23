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
	if err := dumpPacketToFile("request-dump.txt", buffer); err != nil {
		log.Printf("Failed to dump packet: %v", err)
	}
	for _, packageToSend := range ipPaketsToSend.PackagesToSend {
		addr := syscall.SockaddrInet4{
			Port: int(ipPaketsToSend.DestinationPort),
			Addr: ipPaket.DestinationIP,
		}
		if err := dumpPacketToFile("response-dump.txt", packageToSend); err != nil {
			log.Printf("Failed to dump packet: %v", err)
		}
		err := syscall.Sendto(fd, packageToSend, 0, &addr)
		if err != nil {
			log.Printf("Error sending packet: %v", err)
		}
	}
}

func dumpPacketToFile(fileName string, data []byte) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Write hexdump in Wireshark-compatible format
	for i := 0; i < len(data); i += 16 {
		// Write offset
		fmt.Fprintf(file, "%06x  ", i)

		// Write hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(file, "%02x ", data[i+j])
			} else {
				fmt.Fprintf(file, "   ")
			}
			if j == 7 {
				fmt.Fprintf(file, " ") // Extra space between 8th and 9th byte
			}
		}

		// Write ASCII representation
		fmt.Fprintf(file, " |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 { // Printable ASCII characters
				fmt.Fprintf(file, "%c", b)
			} else {
				fmt.Fprintf(file, ".")
			}
		}
		fmt.Fprintf(file, "|\n")
	}
	return nil
}
