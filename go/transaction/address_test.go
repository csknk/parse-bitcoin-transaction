package transaction

import (
	"reflect"
	"testing"
)

func TestSlicesEqual(t *testing.T) {
	tests := []struct {
		name     string
		inputA   []byte
		inputB   []byte
		expected bool
	}{
		{"Equal slices", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"Different lengths", []byte{1, 2, 3}, []byte{1, 2}, false},
		{"Different elements", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := slicesEqual(tt.inputA, tt.inputB)
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}

func TestSlicesEqualReflect(t *testing.T) {
	tests := []struct {
		name     string
		inputA   []byte
		inputB   []byte
		expected bool
	}{
		{"Equal slices", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"Different lengths", []byte{1, 2, 3}, []byte{1, 2}, false},
		{"Different elements", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reflect.DeepEqual(tt.inputA, tt.inputB)
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}
