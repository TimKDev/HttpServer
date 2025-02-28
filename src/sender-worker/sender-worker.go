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

func Start(socket int) {
	log.Println("Start Sender Worker.")
	for {
		nextQueueItem := senderQueue.Pop()
		if nextQueueItem == nil {
			continue
		}
		processMessage(socket, nextQueueItem)
	}
}

func Send(message *SenderMessage, delayedUntil *time.Time) {
	senderQueue.Add(message, delayedUntil)
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
