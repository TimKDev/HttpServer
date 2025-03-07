package queue

import (
	"log"
	"time"
)

type DelayedQueue[T any] struct {
	Message      *T
	DelayedUntil *time.Time
	NextMessage  *DelayedQueue[T]
}

func (queue *DelayedQueue[T]) Add(message *T, delayedUntil *time.Time) {
	lastQueueItem := queue.GetLastQueueItem()
	newQueueItem := DelayedQueue[T]{
		Message:      message,
		DelayedUntil: delayedUntil,
		NextMessage:  nil,
	}
	lastQueueItem.NextMessage = &newQueueItem
}

func (queue *DelayedQueue[T]) Pop() *T {
	if queue == nil {
		return nil
	}
	resQueueItem := queue
	queue = resQueueItem.NextMessage
	if resQueueItem.DelayedUntil != nil && resQueueItem.DelayedUntil.Before(time.Now()) {
		queue.Add(resQueueItem.Message, resQueueItem.DelayedUntil)
		return nil
	}
	return resQueueItem.Message
}

func (queue *DelayedQueue[T]) GetLastQueueItem() *DelayedQueue[T] {
	counter := 0
	for queue.NextMessage != nil {
		queue = queue.NextMessage
		counter++
		if counter > 1000000 {
			log.Fatalln("Infinite Loop in Queue (circular reference). Crash program")
		}
	}

	return queue
}
