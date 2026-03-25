use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serializer;
use sha2::Digest;
use sha2::Sha256;
use std::io;
use std::io::Read;

// read_varint reads an encoded compactSize variable-length integer from an
// input stream and returns the decoded value as a `u64`. The
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
// size (`u16`, `u32`, or `u64`) and then returns the value as a
// `u64`.
//
// If any errors occur during reading or decoding, the function returns early with
// an I/O error.
pub fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8()?;
    match first {
        n @ 0x00..=0xfc => Ok(n as u64),
        0xfd => Ok(r.read_u16::<LittleEndian>()? as u64),
        0xfe => Ok(r.read_u32::<LittleEndian>()? as u64),
        0xff => Ok(r.read_u64::<LittleEndian>()?),
    }
}

pub fn serialize_as_hex<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]> + ?Sized,
    S: Serializer,
{
    let hex = hex::encode(value.as_ref());
    serializer.serialize_str(&hex)
}

/// Serializes byte-oriented values as hex after reversing their byte order.
///
/// This helper exists for Bitcoin data types whose internal representation
/// differs from their canonical human-readable form. In particular, Bitcoin
/// hashes (e.g. txid, block hash, wtxid) are stored internally in
/// little-endian byte order, while the standard textual representation used
/// in RPCs, block explorers, and documentation is big-endian hex.
///
/// This function reverses the byte slice before hex encoding to match that
/// convention.
///
/// Do NOT use this for values whose displayed form matches their stored
/// byte order (e.g. ScriptPubkey, scriptSig, witness elements, raw payloads).
pub fn serialize_as_hex_reversed<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    let mut rev = value.as_ref().to_vec();
    rev.reverse();
    serializer.serialize_str(&hex::encode(rev))
}

pub fn double_hash(raw: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(raw);
    let hash2 = Sha256::digest(hash1);
    hash2.into()
}

/// double_hash_2 takes two &[u8] and concatenates them using sha256.update()
pub fn double_hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h1 = Sha256::new();
    h1.update(a);
    h1.update(b);

    let first = h1.finalize();
    Sha256::digest(first).into()
}

pub fn txid_hex(raw: &[u8]) -> String {
    let mut id = double_hash(raw);
    id.reverse();
    hex::encode(id)
}

// pub fn write_script_element_asm(asm: &mut String, element: &ScriptElement<'_>) -> std::fmt::Result {
//     match element {
//         ScriptElement::Op { opcode } => {
//             // write!(asm, "{}", opcode_name(*opcode))
//         }
//         ScriptElement::Push { opcode: j0x01..=0x4b, data } => {
//             write!(asm, "OP_PUSHBYTES_{} {")
//         }
//     }
// }

pub(crate) fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "OP_0", // Push empty / false

        // 0x01..=0x4b => Cow::Owned(format!("OP_PUSHBYTES_{}", op),
        0x4c => "OP_PUSHDATA1", // Next byte contains number of bytes to push
        0x4d => "OP_PUSHDATA2", // Next 2 bytes (LE) specify number of bytes to push
        0x4e => "OP_PUSHDATA4", // Next 4 bytes (LE) specify number of bytes to push
        0x4f => "OP_1NEGATE",   // Push -1 onto stack
        0x50 => "OP_RESERVED",  // Reserved for future use
        0x51 => "OP_1",         // Push number 1
        0x52 => "OP_2",         // Push number 2
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16", // Push number 16

        // Flow control
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",

        // Stack
        0x6a => "OP_RETURN", // Marks output as provably unspendable
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",

        // Stack ops
        0x76 => "OP_DUP", // Duplicate top stack item

        // Bitwise logic
        0x87 => "OP_EQUAL",       // Are two top stack items equal?
        0x88 => "OP_EQUALVERIFY", // Same as OP_EQUAL + OP_VERIFY

        // Crypto
        0xa9 => "OP_HASH160",  // RIPEMD160(SHA256(x))
        0xac => "OP_CHECKSIG", // Verify digital signature
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG", // Verify multiple signatures
        0xaf => "OP_CHECKMULTISIGVERIFY",

        // Numeric
        0x93 => "OP_ADD", // x + y
        0x94 => "OP_SUB", // x - y
        0x9a => "OP_LESSTHAN",
        0x9c => "OP_EQUAL",
        0x9d => "OP_EQUALVERIFY",

        _ => "OP_UNKNOWN",
    }
}
