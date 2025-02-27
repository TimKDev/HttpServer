package senderworker

import (
	"http-server/helper/queue"
	"log"
	"syscall"
	"time"
)

type SenderMessage struct {
}

// Implement a queue in Go
var senderQueue *queue.DelayedQueue[SenderMessage]

func Start(socket int) {
	for {
		nextQueueItem := senderQueue.Pop()
		if nextQueueItem == nil {
			continue
		}
		ProcessMessage(socket, nextQueueItem)
	}
}

func ProcessMessage(socket int, message *SenderMessage) {
	addr := syscall.SockaddrInet4{
		Port: int(ipPaketsToSend.DestinationPort),
		Addr: ipPaket.DestinationIP,
	}

	err := syscall.Sendto(socket, packageToSend, 0, &addr)
	if err != nil {
		log.Printf("Error sending packet: %v", err)
		return
	}
}

func Send(message *SenderMessage, delayedUntil time.Time) {
	senderQueue.Add(message, delayedUntil)
}
