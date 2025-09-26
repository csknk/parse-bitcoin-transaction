// Package transaction
package transaction

type TxIn struct {
	PrevTxID  [32]byte `json:"prev_tx_id"`
	Vout      uint32   `json:"vout"`
	ScriptSig []byte   `json:"script_sig"`
	Sequence  uint32   `json:"sequence"`
}

// TxOut represents a transaction output in the Bitcoin blockchain. Specifies
// how many satoshis are being transferred & sets the spending conditions.
type TxOut struct {
	// Value is the number of satoshis being transferred in this output.
	Value uint64 `json:"value"`
	// ScriptPubkey is the locking script that specifies the conditions that must be met
	// to spend the output. It is a byte slice that contains the compiled script (also known
	// as "scriptPubKey" or "locking script").
	ScriptPubkey []byte `json:"script_pub_key"`
}

var opcodes = map[byte]string{
	// Constants
	0x00: "OP_0",         // Push empty / false
	0x4c: "OP_PUSHDATA1", // Next byte contains number of bytes to push
	0x4d: "OP_PUSHDATA2", // Next 2 bytes (LE) specify number of bytes to push
	0x4e: "OP_PUSHDATA4", // Next 4 bytes (LE) specify number of bytes to push
	0x4f: "OP_1NEGATE",   // Push -1 onto stack
	0x50: "OP_RESERVED",  // Reserved for future use
	0x51: "OP_1",         // Push number 1
	0x52: "OP_2",         // Push number 2
	0x53: "OP_3",
	0x54: "OP_4",
	0x55: "OP_5",
	0x56: "OP_6",
	0x57: "OP_7",
	0x58: "OP_8",
	0x59: "OP_9",
	0x5a: "OP_10",
	0x5b: "OP_11",
	0x5c: "OP_12",
	0x5d: "OP_13",
	0x5e: "OP_14",
	0x5f: "OP_15",
	0x60: "OP_16", // Push number 16

	// Flow control
	0x63: "OP_IF",
	0x64: "OP_NOTIF",
	0x67: "OP_ELSE",
	0x68: "OP_ENDIF",
	0x69: "OP_VERIFY",

	// Stack
	0x6a: "OP_RETURN", // Marks output as provably unspendable
	0x6b: "OP_TOALTSTACK",
	0x6c: "OP_FROMALTSTACK",

	// Stack ops
	0x76: "OP_DUP", // Duplicate top stack item

	// Bitwise logic
	0x87: "OP_EQUAL",       // Are two top stack items equal?
	0x88: "OP_EQUALVERIFY", // Same as OP_EQUAL + OP_VERIFY

	// Crypto
	0xa9: "OP_HASH160",  // RIPEMD160(SHA256(x))
	0xac: "OP_CHECKSIG", // Verify digital signature
	0xad: "OP_CHECKSIGVERIFY",
	0xae: "OP_CHECKMULTISIG", // Verify multiple signatures
	0xaf: "OP_CHECKMULTISIGVERIFY",

	// Numeric
	0x93: "OP_ADD", // x + y
	0x94: "OP_SUB", // x - y
	0x9a: "OP_LESSTHAN",
	0x9c: "OP_EQUAL",
	0x9d: "OP_EQUALVERIFY",
}
