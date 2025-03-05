package receiverworker

import (
	"http-server/ip-receiver"
	"log"
	"syscall"
)

func Start(fd int) {
	log.Println("Start Receiver Worker")
	log.Println("Waiting for packets... (Press Ctrl+C to stop)")

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

		go process(buf[:n])
	}

}

func process(buffer []byte) {
	err := ipreceiver.HandleIPPackage(buffer)
	if err != nil {
		log.Fatal("IP handeling failed")
	}
}
