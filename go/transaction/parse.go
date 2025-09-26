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

	readInput := func() (TxIn, error) {
		prevTxID := make([]byte, 32)
		if err = binary.Read(r, binary.LittleEndian, prevTxID); err != nil {
			return TxIn{}, fmt.Errorf("error getting previous Tx ID: %w", err)
		}

		// The prevTxID field is stored in little-endian format in raw transactions.
		// To get the canonical txid (as shown in block explorers or for lookup via RPC),
		// we must reverse the byte order to convert it to big-endian.
		prevTxIDReversed := reverseByteSlice(prevTxID)

		var vout uint32
		if err = binary.Read(r, binary.LittleEndian, &vout); err != nil {
			return TxIn{}, err
		}

		scriptLength, scriptLengthErr := readVarInt(r)
		if err != nil {
			return TxIn{}, scriptLengthErr
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

	inputs := []TxIn{}
	for i := range nInputs {
		input, inputErr := readInput()
		if inputErr != nil {
			return nil, fmt.Errorf("can't parse input %d: %w", i, inputErr)
		}
		inputs = append(inputs, input)
	}

	readOutput := func() (TxOut, error) {
		var value uint64
		if err = binary.Read(r, binary.LittleEndian, &value); err != nil {
			return TxOut{}, err
		}

		scriptLength, scriptLengthErr := readVarInt(r)
		if err != nil {
			return TxOut{}, scriptLengthErr
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

	nOutputs, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	outputs := []TxOut{}
	for i := range nOutputs {
		output, outputErr := readOutput()
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

// decodeOuputScript decodes the ScriptPubkeyASM, ScriptPubkeyType and ScriptPubkeyAddress from
// the ScriptPubkey.
// ScriptPubkeyASM is the human-readable assembly representation of the ScriptPubkey.
// ScriptPubkeyType is a string that categorizes the type of script used in the
// ScriptPubkey. Common types include 'pubkeyhash', 'scripthash', 'multisig', 'nulldata'
// ScriptPubkeyAddress is the Bitcoin address associated with the ScriptPubkey, if
// applicable. Not all script types will result in a straightforward address. For
// example, 'nulldata' scripts (used for OP_RETURN outputs) do not have an associated
// address.
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
			asm.WriteString(fmt.Sprintf("OP_PUSHBYTES_%d", opcode))
			hashedKeyLength := int(opcode)

			pubkey := hex.EncodeToString(script[i+1 : i+hashedKeyLength+1])
			asm.WriteString(fmt.Sprintf(" %s", pubkey))
			hashedScriptLenByte = false
			i = i + hashedKeyLength
			continue
		}
		asm.WriteString(opcodes[opcode])
	}
	return asm.String(), scriptType, ""
}

// readVarInt reads the encoded VarInt returns the encoded integer as a uint64
// If first byte < 0xfd → it's the value
// 0xfd → next 2 bytes (uint16)
// 0xfe → next 4 bytes (uint32)
// 0xff → next 8 bytes (uint64)
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

func reverseByteSlice(prevTxID []byte) []byte {
	prevTxIDReversed := make([]byte, 32)
	for i, j := len(prevTxID)-1, 0; i >= 0; i, j = i-1, j+1 {
		prevTxIDReversed[i] = prevTxID[j]
	}
	return prevTxIDReversed
}
