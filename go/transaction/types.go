// Package transaction
package transaction

type TxIn struct {
	PrevTxID  [32]byte `json:"prev_tx_id"`
	Vout      uint32   `json:"vout"`
	ScriptSig []byte   `json:"script_sig"`
	Sequence  uint32   `json:"sequence"`
}

type TxOut struct {
	Value               uint64 `json:"value"`
	ScriptPubKey        []byte `json:"script_pub_key"`
	ScriptPubKeyASM     string `json:"script_pub_key_asm"`
	ScriptPubkeyType    string `json:"script_pubkey_type"`
	ScriptPubkeyAddress string `json:"script_pubkey_address"`
}
