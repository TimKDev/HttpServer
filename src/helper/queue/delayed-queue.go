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
	if queue == nil {
		return
	}
	lastQueueItem := queue.GetLastQueueItem()
	newQueueItem := DelayedQueue[T]{
		Message:      message,
		DelayedUntil: delayedUntil,
		NextMessage:  nil,
	}
	lastQueueItem.NextMessage = &newQueueItem
}

func PopNextItem[T any](queuePointer **DelayedQueue[T]) *T {
	queue := *queuePointer
	if queue == nil {
		return nil
	}
	resQueueItem := queue
	if resQueueItem.DelayedUntil != nil && resQueueItem.DelayedUntil.After(time.Now()) {
		queue.Add(resQueueItem.Message, resQueueItem.DelayedUntil)
		RemoveFirstItem(queuePointer)
		return nil
	}
	RemoveFirstItem(queuePointer)

	return queue.Message

}

func RemoveFirstItem[T any](queuePointer **DelayedQueue[T]) {
	if *queuePointer == nil {
		return
	}
	*queuePointer = (*queuePointer).NextMessage
}

func (queue *DelayedQueue[T]) GetLastQueueItem() *DelayedQueue[T] {
	if queue == nil {
		return nil
	}
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

func NewDelayedQueue[T any](message *T, delayedUntil *time.Time) *DelayedQueue[T] {
	return &DelayedQueue[T]{
		Message:      message,
		DelayedUntil: delayedUntil,
		NextMessage:  nil,
	}
}
