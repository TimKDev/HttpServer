package main

import (
	"fmt"
	"http-server/ip-parser"
	"log"
	"syscall"
)

var detectedCongestions [][4]byte

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
	fmt.Println(buffer)
	ipPaket, err := ipparser.ParseIPPaket(buffer)
	if err != nil {
		log.Printf("Ip parsing error: %v\n", err)
	}
	ipparser.Print(ipPaket)

	if ipPaket.Ecn == ipparser.CE {
		if !ContainsFunc(detectedCongestions, ipPaket.SourceIP, compareIPs) {
			detectedCongestions = append(detectedCongestions, ipPaket.SourceIP)
		}
	}
	//Compute response:
	//Solange mein Transport Layer Congestion Control nicht unterstützt, muss ich in der Response den Wert des ECN Flags auf 0 setzen.
}

func compareIPs(ip1 [4]byte, ip2 [4]byte) bool {
	for i := 0; i < 4; i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}

func Contains[T comparable](slice []T, item T) bool {
	for _, val := range slice {
		if val == item {
			return true
		}
	}
	return false
}

func ContainsFunc[T any](slice []T, item T, compare func(T, T) bool) bool {
	for _, val := range slice {
		if compare(val, item) {
			return true
		}
	}
	return false
}
