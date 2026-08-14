#![allow(unused)]
use crate::libs::utils::serialize_as_hex;
use crate::libs::utils::serialize_as_hex_reversed;
use std::{
    error::Error,
    fmt::{Display, Write},
};
use std::{
    fmt::write,
    io::{self, Cursor, Read},
};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Serialize, Serializer};

use crate::libs::utils::read_varint;

#[derive(Default, Debug, Serialize)]
pub struct TxId(pub [u8; 32]);

impl AsRef<[u8]> for TxId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptSig(Vec<u8>);

impl AsRef<[u8]> for ScriptSig {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ScriptSig {
    pub fn value(&self) -> &Vec<u8> {
        &self.0
    }
}

#[derive(Debug)]
struct ScriptSigDecoded<'a> {
    asm: String,
    pushes: Vec<&'a [u8]>,
}

#[derive(Debug)]
pub enum DecodeScriptSigError {
    Read(std::io::Error),
    Fmt(std::fmt::Error),
}

impl Display for DecodeScriptSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeScriptSigError::Read(e) => write!(f, "read error: {e}"),
            DecodeScriptSigError::Fmt(e) => write!(f, "formatting error: {e}"),
        }
    }
}

impl Error for DecodeScriptSigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DecodeScriptSigError::Read(error) => Some(error),
            DecodeScriptSigError::Fmt(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for DecodeScriptSigError {
    fn from(value: std::io::Error) -> Self {
        DecodeScriptSigError::Read(value)
    }
}

impl From<std::fmt::Error> for DecodeScriptSigError {
    fn from(value: std::fmt::Error) -> Self {
        DecodeScriptSigError::Fmt(value)
    }
}

#[derive(Default, Debug, Serialize)]
pub struct TxIn {
    pub prev_tx_id: TxId,
    pub vout: u32,
    pub script_sig: ScriptSig,
    pub sequence: u32,
}

#[derive(Debug, Serialize)]
pub struct TxInView<'a> {
    #[serde(serialize_with = "serialize_as_hex_reversed")]
    pub prev_tx_id: &'a TxId,
    pub vout: u32,
    #[serde(serialize_with = "serialize_as_hex")]
    pub script_sig: &'a ScriptSig,
    pub script_sig_asm: Option<String>,
    pub sequence: u32,
}

impl<'a> From<&'a TxIn> for TxInView<'a> {
    fn from(tx_input: &'a TxIn) -> Self {
        let script_sig_asm = decode_script_sig(tx_input.script_sig.as_ref())
            .ok()
            .map(|decoded| decoded.asm);

        Self {
            prev_tx_id: &tx_input.prev_tx_id,
            vout: tx_input.vout,
            script_sig: &tx_input.script_sig,
            script_sig_asm,
            sequence: tx_input.sequence,
        }
    }
}

// read_input reads and unpacks the input data from the provided io.Reader.
// The function reads the previous transaction ID (32 bytes), vout (4 bytes), script length (variable length),
// script signature (variable length), and sequence number (4 bytes) from the reader.
// The txid field is stored in little-endian format in raw transactions,
// so it needs to be reversed to convert it to big-endian for canonical txid.
// The unpacked data is used to create and return a TxIn struct.
// - 32 byte txid
// - varint of script_length
// - script_sig of length script_length
// - sequence: u32
pub fn read_input<R: Read>(r: &mut R) -> io::Result<TxIn> {
    let mut txid = [0u8; 32];
    r.read_exact(&mut txid)?;

    // vout: read next 4 bytes (u32)
    let vout = r.read_u32::<LittleEndian>()?;

    // script_length: read_varint()
    let script_length = read_varint(r)? as usize;

    // script signature: read script_length bytes into Vec<u8>
    let mut script_sig = vec![0u8; script_length];
    r.read_exact(&mut script_sig)?;

    // Sequence: 4 bytes (u32)
    let sequence = r.read_u32::<LittleEndian>()?;

    Ok(TxIn {
        prev_tx_id: TxId(txid),
        vout,
        script_sig: ScriptSig(script_sig),
        sequence,
    })
}

/// decode_script
/// TODO: Utilise same approach [start..end] for the other cursor based function that decodes output
/// script pubkey
fn decode_script_sig<'a>(script: &'a [u8]) -> Result<ScriptSigDecoded<'a>, DecodeScriptSigError> {
    let mut pushes = Vec::new();
    let mut cursor = Cursor::new(script);
    let mut asm = String::new();
    let mut first = true;
    while (cursor.position() as usize) < script.len() {
        if !first {
            asm.push(' ');
        }
        let opcode = cursor.read_u8()?;
        if (0x01..0x4b).contains(&opcode) {
            write!(&mut asm, "OP_PUSHBYTES_{}", opcode)?;
        }

        let start = cursor.position() as usize;
        let len = opcode as usize;
        let end = start + len;
        pushes.push(&script[start..end]);
        write!(asm, " {}", hex::encode(&script[start..end]));
        cursor.set_position(end as u64);
        first = false;
    }

    Ok(ScriptSigDecoded { asm, pushes })
}
