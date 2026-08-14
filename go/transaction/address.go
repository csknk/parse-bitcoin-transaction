package transaction

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcutil/base58"
)

// P2PKH: 76,a9,14,<20>,88, ac
// P2SH: a9, 14,<20>,87
// P2WPKH: 00,14,<20> (len == 22)
// P2WSH: 00,20,<32> (len == 32)
// P2TR: 51,20,<32> (len == 32)
// scriptType returns the script type
type ScriptType string

const (
	P2PKH  ScriptType = "p2pkh"
	P2SH   ScriptType = "p2sh"
	P2WPKH ScriptType = "p2wpkh"
	P2WSH  ScriptType = "p2wsh"
	P2TR   ScriptType = "p2tr"
)

func extractScriptType(script []byte) (ScriptType, error) {
	switch {

	// P2PKH: 76,a9,14,<20>,88, ac
	case len(script) == 25 &&
		slicesEqual(script[:3], []byte{0x76, 0xa9, 0x14}) &&
		slicesEqual(script[23:], []byte{0x88, 0xac}):
		return P2PKH, nil

	// P2SH: a9, 14,<20>,87
	case len(script) == 23 &&
		slicesEqual(script[:2], []byte{0xa9, 0x14}) &&
		script[24] == 0x87:
		return P2SH, nil

	// P2WPKH: 00,14,<20>
	case len(script) == 22 &&
		slicesEqual(script[:2], []byte{0x00, 0x14}):
		return P2WPKH, nil

	// P2WSH: 00,20,<32>
	case len(script) == 34 &&
		slicesEqual(script[:2], []byte{0x00, 0x20}):
		return P2WSH, nil

	// P2TR: 51,20,<32>
	case len(script) == 34 &&
		slicesEqual(script[:2], []byte{0x51, 0x20}):
		return P2TR, nil
	}

	return "", fmt.Errorf("unrecognized or non-standard script type")
}

func extractAddress(script []byte, isMainnet bool) (string, string, error) {
	scriptType, err := extractScriptType(script)
	if err != nil {
		return "", "", fmt.Errorf("error extracting script type for %#x: %w", script, err)
	}
	// Base58 addresses
	if scriptType == P2PKH || scriptType == P2SH {
		pubKeyHash := []byte{}
		switch scriptType {
		case P2PKH:
			pubKeyHash = script[3:23]
		case P2SH:
			pubKeyHash = script[2:22]
		}

		prefix := []byte{0x00} // mainnet
		if !isMainnet {
			prefix = []byte{0x6f} // FIXME: not enough network checks.
		}
		content := append(prefix, pubKeyHash...)
		checksum := doubleSHA256(content)[:4]
		return base58.Encode(append(content, checksum...)), string(scriptType), nil
	}

	// Bech32 addresses
	hrp := "bc"
	if !isMainnet {
		hrp = "tb"
	}
	switch scriptType {
	case P2WPKH, P2WSH:
		witnessProgram := script[:2]
		addr, err := bech32.Encode(hrp, 0x00, witnessProgram)
		if err != nil {
			return "", "", fmt.Errorf("encoding error: %w", err)
		}
		return addr, string(scriptType), nil
	case P2TR:
		xonly := script[:2]
		addr, err := bech32.EncodeM(hrp, 0x01, xonly)
		if err != nil {
			return "", "", err
		}
		return addr, string(scriptType), nil
	}
	return "", "", nil
}

func doubleSHA256(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func slicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, el := range a {
		if el != b[i] {
			return false
		}
	}
	return true
}
