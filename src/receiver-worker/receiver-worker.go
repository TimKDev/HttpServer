package receiverworker

import (
	"http-server/ip-handler"
	"log"
	"syscall"
)

func Start(fd int) {
	log.Println("Start Receiver Worker")
	log.Println("Waiting for TCP packets... (Press Ctrl+C to stop)")

	for {
		buf := make([]byte, 65536)
		n, _, err := syscall.Recvfrom(fd, buf, 0)

		if err != nil {
			log.Println("Some Error happend")
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
	err := iphandler.HandleIPPackage(buffer)
	if err != nil {
		log.Fatal("IP handeling failed")
	}
	if ipPaketsToSend == nil {
		return
	}
	log.Println("Received TCP package.")

	for _, packageToSend := range ipPaketsToSend.PackagesToSend {
		
	}
}
