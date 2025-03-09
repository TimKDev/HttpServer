package queue

import (
	"testing"
	"time"
)

func TestDelayedQueue(t *testing.T) {
	t.Run("should handle empty queue", func(t *testing.T) {
		var queue *DelayedQueue[string]
		result := PopNextItem(&queue)
		if result != nil {
			t.Errorf("Expected nil from empty queue, got %v", result)
		}
	})

	t.Run("should add and pop item", func(t *testing.T) {
		msg := "test message"
		queue := &DelayedQueue[string]{
			Message:      &msg,
			DelayedUntil: nil,
			NextMessage:  nil,
		}

		msg2 := "second message"
		queue.Add(&msg2, nil)

		result := PopNextItem(&queue)
		if *result != "test message" {
			t.Errorf("Expected 'test message', got %v", *result)
		}

		result = PopNextItem(&queue)
		if *result != "second message" {
			t.Errorf("Expected 'second message', got %v", *result)
		}

		result = PopNextItem(&queue)
		if result != nil {
			t.Errorf("Expected nil, but got value %v", *result)
		}
	})

	t.Run("should handle delayed messages", func(t *testing.T) {
		msg := "delayed message"
		future := time.Now().Add(time.Hour)
		queue := &DelayedQueue[string]{
			Message:      &msg,
			DelayedUntil: &future,
			NextMessage:  nil,
		}

		result := PopNextItem(&queue)
		if result != nil {
			t.Errorf("Expected nil for delayed message, got %v", *result)
		}
	})
}
