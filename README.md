# Bitcoin Transaction Parsing

This is an educational project that attempts to parse Bitcoin transactions from first principles, without significant external dependencies.

The objective is to decode Bitcoin transactions from raw bytes.

## Overall Approach

- Define suitable data structures
- Read binary data sequentially, populating data structures @
- Helper functions: determine field sizes based on CompactSize integers
-

## Legacy Transaction Structure

The legacy transaction byte mapping is as follows:

Version (4 bytes)
Input count (CompactSize integer)
[Inputs]:

- Prev txid (32 bytes)
- Prev index (4 bytes)
- Script length (CompactSize integer)
- Script (n bytes)
- Sequence (4 bytes)

Output count (CompactSize integer)
[Outputs]:

- Value (8 bytes)
- Script length (CompactSize integer)
- Script (n bytes)

Locktime (4 bytes)

## CompactSize Variable Length Integers

Bitcoin has multiple methods for encoding variable length integers, with different methods used in different parts of the codebase.

The raw transaction format and several peer-to-peer network messages use a type of variable-length integer to indicate the number of bytes in a following piece of data. This provides a compact way of representing integers of variable size whilst minimising the space taken up. For example, if we knew that the largest integer that we would handle could be represented by 8 bytes, we could just allocate 8 bytes to this field. If most of the time the field encodes numbers less than 255 (which can be represented in a single byte), then most of the time we would be wasting 7 bytes on every such value.

In the context of decoding a Bitcoin transaction, the encoding protocol used to encode variable length integers is known as [CompactSize][compact integers]. This involves prepending(prefixing) integers with a byte that indicates integer length for numbers greater than 252.

When parsing a transaction, the number of inputs is specified by a CompactSize encoded integer. Once decoded, the parser knows how many inputs to process.

1. The transaction data starts with the version number.
2. Next, a CompactSize encoded integer specifies the number of inputs.
3. The CompactSize integer is at least 1 byte and may be as large as 9 bytes.
4. The parser reads that many inputs, each of which has its own structure.
5. Following the inputs, another CompactSize encoded integer specifies the number of outputs.
6. The parser then reads the specified number of outputs.

### CompactSize Encoding

| Prefix   | Range (decimal)        | Encoding                                            | Total bytes |
| :------- | :--------------------- | :-------------------------------------------------- | :---------- |
| `< 0xfd` | 0 – 252                | The value itself (1 byte)                           | 1           |
| `0xfd`   | 253 – 65,535           | `0xfd` followed by 2-byte **little-endian** integer | 3           |
| `0xfe`   | 65,536 – 4,294,967,295 | `0xfe` + 4-byte **little-endian** integer           | 5           |
| `0xff`   | ≥ 4,294,967,296        | `0xff` + 8-byte **little-endian** integer           | 9           |

[compact integers]: https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers

## Parse Bitcoin Transactions in Production

If you want to parse a Bitcoin transaction, you should probably use btcd something like this:

```go
package main

import (
 "bytes"
 "encoding/hex"
 "fmt"
 "log"
 "strings"

 "github.com/btcsuite/btcd/wire"
)

func main() {
 // Example raw transaction (mainnet P2PKH)
 rawTx := "010000000104dde43b0e4724f1e3b45782a9bfbcc91ea764c7cb1c245fba" +
  "1fefa175c3a5d0010000006a4730440220519f7867349790ee441e83e545afbd25" +
  "b954a34e0733cd4da3b5f1e5588625050220166730d053c3672973bcb2bb1a977b" +
  "747837023b647e3af2ac9c15728b0681da01210236ccb7ee3a9f154127f384a058" +
  "70c4fd86a8727eab7316f1449a0b9e65bfd90dffffffff025d3601000000000019" +
  "76a91478364a559841329304188cd791ad9dabbb2a3fdb88ac605b030000000000" +
  "1976a914064e0aa817486573f4c2de09f927697e1e6f233f88ac00000000"

 // Decode hex to bytes
 txBytes, err := hex.DecodeString(rawTx)
 if err != nil {
  log.Fatalf("hex decode failed: %v", err)
 }

 // Deserialize into a wire.MsgTx
 var msgTx wire.MsgTx
 if err := msgTx.DeserializeNoWitness(hex.NewDecoder(strings.NewReader(rawTx))); err != nil {
  log.Fatalf("tx deserialize failed: %v", err)
 }

 // OR simply:
 if err := msgTx.Deserialize(bytes.NewReader(txBytes)); err != nil {
  log.Fatalf("Deserialize failed: %v", err)
 }

 // Print fields
 fmt.Printf("Version: %d\n", msgTx.Version)
 fmt.Printf("Inputs: %d\n", len(msgTx.TxIn))
 fmt.Printf("Outputs: %d\n", len(msgTx.TxOut))
 fmt.Printf("LockTime: %d\n", msgTx.LockTime)

 for i, output := range msgTx.TxOut {
  fmt.Printf("output %d: %#v\n", i, output)
 }
}

```
