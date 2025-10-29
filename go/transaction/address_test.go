package transaction

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func TestExtractScriptType(t *testing.T) {
	tests := []struct {
		name      string
		hexScript string
		want      ScriptType
		wantErr   bool
	}{
		{
			name:      "P2PKH",
			hexScript: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
			want:      P2PKH,
		},
		{
			name:      "P2SH",
			hexScript: "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87",
			want:      P2SH,
		},
		{
			name:      "P2WPKH",
			hexScript: "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba",
			want:      P2WPKH,
		},
		{
			name:      "P2WSH",
			hexScript: "00205f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953",
			want:      P2WSH,
		},
		{
			name:      "P2TR",
			hexScript: "51205f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953",
			want:      P2TR,
		},
		{
			name:      "Non-standard",
			hexScript: "6a24b9e11b6d0f68e4b8b4b7", // OP_RETURN ...
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, err := hex.DecodeString(tt.hexScript)
			if err != nil {
				t.Fatalf("hex decode error: %v", err)
			}

			got, err := extractScriptType(script)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

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

func Test_extractAddress(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		script         string
		isMainnet      bool
		wantAddr       string
		wantScriptType string
		wantErr        bool
	}{
		{
			script:         "00140d6c887ce96acf1fdd900f24f4e5cbffbef4683c",
			isMainnet:      true,
			wantAddr:       "bc1qp4kgsl8fdt83lhvspuj0fewtl7l0g6pu3k87wq",
			wantScriptType: "p2wpkh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, err := hex.DecodeString(tt.script)
			if err != nil {
				t.Errorf("faulty test: script can't be decoded to bytes: %v", err)
			}
			gotAddress, gotScriptType, gotErr := extractAddress(script, tt.isMainnet)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("extractAddress() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("extractAddress() succeeded unexpectedly")
			}
			if gotAddress != tt.wantAddr {
				t.Errorf("extractAddress() address = %v, want %v", gotAddress, tt.wantAddr)
			}
			if gotScriptType != tt.wantScriptType {
				t.Errorf("extractAddress() = %v, want %v", gotScriptType, tt.wantScriptType)
			}
			fmt.Printf("address computed: %s\n", gotAddress)
		})
	}
}
