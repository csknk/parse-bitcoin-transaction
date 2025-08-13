package transaction

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestReadVarInt(t *testing.T) {
	tests := []struct {
		input    []byte
		expected uint64
	}{
		{[]byte{0x01}, 1},
		{[]byte{0xfc}, 252},
		{[]byte{0xfd, 0xe8, 0x03}, 1000},
		{[]byte{0xfe, 0x40, 0x42, 0x0f, 0x00}, 1000000},
		{
			[]byte{0xff, 0x00, 0xCa, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00},
			1000000000,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Test %d", i+1), func(t *testing.T) {
			r := bytes.NewReader(test.input)
			result, err := readVarInt(r)
			if err != nil {
				t.Errorf("Error reading VarInt: %v", err)
			}
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}
