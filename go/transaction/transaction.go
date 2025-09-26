package transaction

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
)

type Transaction struct {
	RawTx    []byte  `json:"raw_tx"`
	Version  uint32  `json:"version"`
	TxIns    []TxIn  `json:"tx_ins"`
	TxOuts   []TxOut `json:"tx_outs"`
	Locktime uint32  `json:"locktime"`
}

func NewTransaction(rawTx string) (*Transaction, error) {
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, err
	}
	return &Transaction{
		RawTx: txBytes,
	}, nil
}

func (t *Transaction) Parse() error {
	txReader := bytes.NewReader(t.RawTx)
	tx, err := ParseTx(txReader)
	if err != nil {
		return err
	}
	t.TxIns = tx.TxIns
	t.TxOuts = tx.TxOuts
	t.Locktime = tx.Locktime
	t.Version = tx.Version
	return nil
}

// MarshalJSON customizes the JSON marshaling for TxIn.
func (txIn *TxIn) MarshalJSON() ([]byte, error) {
	type Alias TxIn // Create an alias to avoid recursion
	return json.Marshal(&struct {
		PrevTxIDHex string `json:"prev_tx_id"`
		ScriptSig   string `json:"script_sig"`
		*Alias
	}{
		PrevTxIDHex: hex.EncodeToString(txIn.PrevTxID[:]),
		ScriptSig:   hex.EncodeToString(txIn.ScriptSig),
		Alias:       (*Alias)(txIn),
	})
}

func (txOut *TxOut) MarshalJSON() ([]byte, error) {
	type Alias TxOut
	scriptPubkeyASM, scriptPubkeyType, scriptPubkeyAddress := decodeOuputScript(txOut.ScriptPubkey)
	return json.Marshal(&struct {
		ScriptPubkey        string `json:"script_pubkey"`
		ScriptPubkeyASM     string `json:"script_pubkey_asm"`
		ScriptPubkeyType    string `json:"script_pubkey_type"`
		ScriptPubkeyAddress string `json:"script_pubkey_address"`
		*Alias
	}{
		ScriptPubkey:        hex.EncodeToString(txOut.ScriptPubkey),
		ScriptPubkeyASM:     scriptPubkeyASM,
		ScriptPubkeyType:    scriptPubkeyType,
		ScriptPubkeyAddress: scriptPubkeyAddress,
		Alias:               (*Alias)(txOut),
	})
}
