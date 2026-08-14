package transaction

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
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
		// --- v0 segwit (bech32) ---
		{
			name:           "P2WPKH mainnet (BIP173 test vector)",
			script:         "0014751e76e8199196d454941c45d1b3a323f1433bd6",
			isMainnet:      true,
			wantAddr:       "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantScriptType: "p2wpkh",
		},
		{
			name:           "P2WPKH mainnet (your current test)",
			script:         "00140d6c887ce96acf1fdd900f24f4e5cbffbef4683c",
			isMainnet:      true,
			wantAddr:       "bc1qp4kgsl8fdt83lhvspuj0fewtl7l0g6pu3k87wq",
			wantScriptType: "p2wpkh",
		},
		{
			name:           "P2WSH testnet (BIP173 test vector)",
			script:         "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			isMainnet:      false,
			wantAddr:       "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
			wantScriptType: "p2wsh",
		},

		// --- Taproot v1 (bech32m) ---

		{
			name:           "P2TR mainnet (bech32m example)",
			script:         "5120af9871a3e9464d463e2ad181028dbc00f4199e36716ed46efc442dd7fb0810ee",
			isMainnet:      true,
			wantAddr:       "bc1p47v8rglfgex5v0326xqs9rduqr6pn83kw9hdgmhugska07cgzrhqjn9kns",
			wantScriptType: "p2tr",
		},

		// --- Legacy (base58) ---

		{
			name: "P2PKH mainnet (hash160 = 20 zero bytes)",
			// 76 a9 14 <20 zero bytes> 88 ac
			script:         "76a914000000000000000000000000000000000000000088ac",
			isMainnet:      true,
			wantAddr:       "1111111111111111111114oLvT2",
			wantScriptType: "p2pkh",
		},
		{
			name: "P2SH mainnet (example pair)",
			// a9 14 <20 bytes> 87
			script:         "a9144139954acf570dbcdaebee8a3ebe1d8033fc472b87",
			isMainnet:      true,
			wantAddr:       "37dtpxjTw9THz8gaY7zkzPebTyBqGWSWeW",
			wantScriptType: "p2sh",
		},

		// --- Non-address / invalids you should reject ---

		{
			name:      "OP_RETURN (nulldata) – no address",
			script:    "6a0548656c6c6f", // OP_RETURN "Hello"
			isMainnet: true,
			wantErr:   true,
		},
		{
			name:      "Segwit v0 wrong program length (19 bytes) – invalid",
			script:    "00130102030405060708090a0b0c0d0e0f10111213",
			isMainnet: true,
			wantErr:   true,
		},
		{
			name: "Unknown witness version v2 (32 bytes) – unsupported",
			// OP_2 (0x52) + push 32 (0x20) + 32 bytes
			script:    "5220" + strings.Repeat("aa", 32),
			isMainnet: true,
			wantErr:   true,
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
