# Bitcoin Transaction Parsing

## Legacy Transaction Structure

Version (4 bytes)
Input count (varint)
[Inputs]:

- Prev txid (32 bytes)
- Prev index (4 bytes)
- Script length (varint)
- Script (n bytes)
- Sequence (4 bytes)

Output count (varint)
[Outputs]:

- Value (8 bytes)
- Script length (varint)
- Script (n bytes)

Locktime (4 bytes)
