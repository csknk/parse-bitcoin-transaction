package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func ParseTx(r io.Reader) (*Transaction, error) {
	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, err
	}
	nInputs, err := readVarInt(r)
	if err != nil {
		return nil, err
	}

	inputs := []TxIn{}
	for i := range nInputs {
		input, inputErr := readInput(r)
		if inputErr != nil {
			return nil, fmt.Errorf("can't parse input %d: %w", i, inputErr)
		}
		inputs = append(inputs, input)
	}

	nOutputs, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	outputs := []TxOut{}
	for i := range nOutputs {
		output, outputErr := readOutput(r)
		if outputErr != nil {
			return nil, fmt.Errorf("can't parse output %d: %w", i, outputErr)
		}
		outputs = append(outputs, output)
	}

	var lockTime uint32
	if err = binary.Read(r, binary.LittleEndian, &lockTime); err != nil {
		return nil, err
	}

	return &Transaction{
		TxIns:    inputs,
		TxOuts:   outputs,
		Version:  version,
		Locktime: lockTime,
	}, nil
}

// decodeOuputScript decodes the ScriptPubkeyASM, ScriptPubkeyType and
// ScriptPubkeyAddress from the ScriptPubkey. ScriptPubkeyASM is the
// human-readable assembly representation of the ScriptPubkey. ScriptPubkeyType
// is a string that categorizes the type of script used in the ScriptPubkey.
// Common types include 'pubkeyhash', 'scripthash', 'multisig', 'nulldata'
// ScriptPubkeyAddress is the Bitcoin address associated with the ScriptPubkey,
// if applicable.
//
// Note: Not all script types will result in a straightforward address. For
// example, 'nulldata' scripts (used for OP_RETURN outputs) do not have an
// associated address.
func decodeOuputScript(script []byte) (string, string, string) {
	var asm strings.Builder
	var hashedScriptLenByte bool
	var scriptType string
	if bytes.Equal(script[:3], []byte{0x76, 0xa9, 0x14}) {
		scriptType = "pkpkh"
	}
	for i := 0; i < len(script); i++ {
		if i > 0 {
			asm.WriteString(" ")
		}
		opcode := script[i]
		if opcode == 0xa9 {
			hashedScriptLenByte = true
		}
		if hashedScriptLenByte && opcode >= 0x01 && opcode <= 0x4b {
			fmt.Fprintf(&asm, "OP_PUSHBYTES_%d", opcode)
			hashedKeyLength := int(opcode)

			pubkey := hex.EncodeToString(script[i+1 : i+hashedKeyLength+1])
			fmt.Fprintf(&asm, " %s", pubkey)
			hashedScriptLenByte = false
			i = i + hashedKeyLength
			continue
		}
		asm.WriteString(opcodes[opcode])
	}
	addr, _, err := extractAddress(script, true)
	if err != nil {
		return "", "", ""
	}
	return asm.String(), scriptType, addr
}

func decodeScriptSig(scriptSig []byte) (scriptSigASM string, signature, pubKey []byte) {
	var asm strings.Builder
	for i := 0; i < len(scriptSig); i++ {
		if i > 0 {
			asm.WriteString(" ")
		}
		opcode := scriptSig[i]
		// TODO: expand these rules to account for all tx types
		if opcode >= 0x01 && opcode <= 0x4b {
			fmt.Fprintf(&asm, "OP_PUSHBYTES_%d", opcode)
		}

		pushData := scriptSig[i+1 : i+int(opcode)+1]
		asm.WriteString(" ")
		asm.WriteString(hex.EncodeToString(pushData))
		if i == 0 {
			signature = pushData
		}
		if i > 0 && opcode == 0x21 || opcode == 0x40 {
			pubKey = pushData
		}
		i = i + int(opcode)
	}
	scriptSigASM = asm.String()
	return scriptSigASM, signature, pubKey
}

// readVarInt reads an encoded compactSize variable-length integer from an
// input stream (`io.Reader`) and returns the decoded value as a `uint64`. The
// function follows the Bitcoin protocol for encoding variable-length integers:
//
// - If the first byte is less than `0xfd`, it represents the integer value directly.
// - If the first byte is `0xfd`, the next 2 bytes are read as a `uint16`.
// - If the first byte is `0xfe`, the next 4 bytes are read as a `uint32`.
// - If the first byte is `0xff`, the next 8 bytes are read as a `uint64`.
//
// The function reads the first byte from the input stream and then switches
// over its value to determine how many bytes to read next. It reads the
// appropriate number of bytes into an integer variable of the corresponding
// size (`uint16`, `uint32`, or `uint64`) and then returns the value as a
// `uint64`.
//
// If any errors occur during reading or decoding, the function returns an
// error.
func readVarInt(r io.Reader) (uint64, error) {
	var first uint8
	if err := binary.Read(r, binary.LittleEndian, &first); err != nil {
		return 0, fmt.Errorf("error reading first byte: %w", err)
	}
	switch first {
	case 0xfd:
		// 2 bytes of data
		var byteValue uint16
		if err := binary.Read(r, binary.LittleEndian, &byteValue); err != nil {
			return 0, err
		}
		return uint64(byteValue), nil
	case 0xfe:
		// 4 bytes of data
		var byteValue uint32
		if err := binary.Read(r, binary.LittleEndian, &byteValue); err != nil {
			return 0, err
		}
		return uint64(byteValue), nil
	case 0xff:
		// 8 bytes of data
		var byteValue uint64
		if err := binary.Read(r, binary.LittleEndian, &byteValue); err != nil {
			return 0, err
		}
		return byteValue, nil

	default:
		return uint64(first), nil
	}
}

// readInput reads and unpacks the input data from the provided io.Reader.
// The function reads the previous transaction ID (32 bytes), vout (4 bytes), script length (variable length),
// script signature (variable length), and sequence number (4 bytes) from the reader.
// The prevTxID field is stored in little-endian format in raw transactions,
// so it needs to be reversed to convert it to big-endian for canonical txid.
// The unpacked data is used to create and return a TxIn struct.
// If any error occurs during the unpacking process, an error is returned along with the TxIn struct.
func readInput(r io.Reader) (TxIn, error) {
	prevTxID := make([]byte, 32)
	if err := binary.Read(r, binary.LittleEndian, prevTxID); err != nil {
		return TxIn{}, fmt.Errorf("error getting previous Tx ID: %w", err)
	}

	// The prevTxID field is stored in little-endian format in raw transactions.
	// To get the canonical txid (as shown in block explorers or for lookup via RPC),
	// we must reverse the byte order to convert it to big-endian.
	prevTxIDReversed := reverseByteSlice(prevTxID)

	var vout uint32
	if err := binary.Read(r, binary.LittleEndian, &vout); err != nil {
		return TxIn{}, err
	}

	scriptLength, err := readVarInt(r)
	if err != nil {
		return TxIn{}, err
	}

	scriptSig := make([]byte, scriptLength)
	if err = binary.Read(r, binary.LittleEndian, scriptSig); err != nil {
		return TxIn{}, err
	}

	var sequence uint32
	if err = binary.Read(r, binary.LittleEndian, &sequence); err != nil {
		return TxIn{}, err
	}

	return TxIn{
		PrevTxID:  [32]byte(prevTxIDReversed),
		Vout:      vout,
		ScriptSig: scriptSig,
		Sequence:  sequence,
	}, nil
}

func readOutput(r io.Reader) (TxOut, error) {
	var value uint64
	if err := binary.Read(r, binary.LittleEndian, &value); err != nil {
		return TxOut{}, err
	}

	scriptLength, err := readVarInt(r)
	if err != nil {
		return TxOut{}, err
	}
	script := make([]byte, scriptLength)
	if err = binary.Read(r, binary.LittleEndian, script); err != nil {
		return TxOut{}, err
	}

	return TxOut{
		Value:        value,
		ScriptPubkey: script,
	}, nil
}

// reverseByteSlice
func reverseByteSlice(prevTxID []byte) []byte {
	prevTxIDReversed := make([]byte, 32)
	for i, j := len(prevTxID)-1, 0; i >= 0; i, j = i-1, j+1 {
		prevTxIDReversed[i] = prevTxID[j]
	}
	return prevTxIDReversed
}
