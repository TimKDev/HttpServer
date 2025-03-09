package senderworker

import (
	"http-server/helper/queue"
	"log"
	"syscall"
	"time"
)

type SenderMessage struct {
	DestinationIP   [4]byte
	DestinationPort uint16
	IPPaket         []byte
}

var senderQueue *queue.DelayedQueue[SenderMessage]

func Start() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("socket creation error: %v", err)
	}

	// Set IP_HDRINCL to tell kernel we're including our own IP header
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("failed to set IP_HDRINCL: %v", err)
	}

	log.Println("Send socket created successfully")
	log.Println("Start Sender Worker.")
	for {
		if senderQueue == nil {
			continue
		}
		nextQueueItem := queue.PopNextItem(&senderQueue)
		if nextQueueItem == nil {
			continue
		}
		go processMessage(fd, nextQueueItem)
	}
}

func Send(message *SenderMessage, delayedUntil *time.Time) {
	if senderQueue == nil {
		senderQueue = &queue.DelayedQueue[SenderMessage]{
			Message:      message,
			DelayedUntil: delayedUntil,
			NextMessage:  nil,
		}
	} else {
		senderQueue.Add(message, delayedUntil)
	}
}

func processMessage(socket int, message *SenderMessage) {
	addr := syscall.SockaddrInet4{
		Port: int(message.DestinationPort),
		Addr: message.DestinationIP,
	}

	err := syscall.Sendto(socket, message.IPPaket, 0, &addr)
	if err != nil {
		log.Printf("Error sending packet: %v", err)
		return
	}
}
