package transaction

import (
	"encoding/binary"
	"fmt"
	"io"
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
		prevTxIDReversed := make([]byte, 32)
		for i, j := len(prevTxID)-1, 0; i >= 0; i, j = i-1, j+1 {
			prevTxIDReversed[i] = prevTxID[j]
		}

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
			ScriptPubKey: script,
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
