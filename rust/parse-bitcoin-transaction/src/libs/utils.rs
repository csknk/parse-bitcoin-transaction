use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
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
