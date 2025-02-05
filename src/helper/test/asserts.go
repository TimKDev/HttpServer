package test

import (
	"testing"
)

func AssertSliceEquality[T comparable](t *testing.T, actual []T, expected []T) {
	if len(actual) != len(expected) {
		t.Errorf("Slice length mismatch: got %d elements, want %d elements\n", len(actual), len(expected))
		return
	}

	for i := range actual {
		if actual[i] != expected[i] {
			t.Errorf("Slice mismatch at index %d: got %v, want %v\n", i, actual[i], expected[i])
		}
	}
}

func AssertEquality[T comparable](t *testing.T, actual T, expected T) {
	if actual != expected {
		t.Errorf("Expected Value: %v to be equal to %v", actual, expected)
		return
	}
}

func AssertError(t *testing.T, err error, expectedErrorMessage string) {
	if err == nil {
		t.Errorf("Expected Error Message: %s\n", expectedErrorMessage)
		t.Error("Actual Error Message: nil")
		return
	}
	if err.Error() != expectedErrorMessage {
		t.Errorf("Expected Error Message: %s\n", expectedErrorMessage)
		t.Errorf("Actual Error Message: %s", err.Error())
	}
}

func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Expected success but got error: %s", err.Error())
	}
}
