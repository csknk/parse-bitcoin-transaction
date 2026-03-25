use crate::libs::utils::{opcode_name, serialize_as_hex, serialize_as_hex_reversed};
use std::fmt::Write;
use std::io::{self, Cursor, Read};
use std::{error::Error, fmt::Display};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

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

#[derive(Debug)]
pub enum DecodeScriptSigError {
    IO(std::io::Error),
    Fmt(std::fmt::Error),
    UnexpectedEof { needed: usize, remaining: usize },
    PushLengthTooLarge { len: usize, max: usize },
}

impl Display for DecodeScriptSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeScriptSigError::IO(e) => write!(f, "read error: {e}"),
            DecodeScriptSigError::Fmt(e) => write!(f, "formatting error: {e}"),
            DecodeScriptSigError::UnexpectedEof { needed, remaining } => write!(
                f,
                "unexpected EOF: needed {needed} bytes, only {remaining} remaining"
            ),
            DecodeScriptSigError::PushLengthTooLarge { len, max } => {
                write!(
                    f,
                    "push length too large: needed {len}, max length is {max}"
                )
            }
        }
    }
}

impl Error for DecodeScriptSigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DecodeScriptSigError::IO(error) => Some(error),
            DecodeScriptSigError::Fmt(error) => Some(error),
            // Terminal domain errors
            DecodeScriptSigError::UnexpectedEof { .. } => None,
            DecodeScriptSigError::PushLengthTooLarge { .. } => None,
        }
    }
}

impl From<std::io::Error> for DecodeScriptSigError {
    fn from(value: std::io::Error) -> Self {
        DecodeScriptSigError::IO(value)
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
        let script_sig_asm = decode_script_sig(tx_input.script_sig.as_ref()).ok();

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

#[derive(Debug)]
pub(crate) enum ScriptElement<'a> {
    Op { opcode: u8 },
    Push { opcode: u8, data: &'a [u8] },
}

/// decode_script
fn parse_script<'a>(script: &'a [u8]) -> Result<Vec<ScriptElement<'a>>, DecodeScriptSigError> {
    let mut cursor = Cursor::new(script);
    let mut elements = Vec::new();

    while (cursor.position() as usize) < script.len() {
        let opcode = cursor.read_u8()?;

        let push_len = match opcode {
            0x01..=0x4b => Some(opcode as usize),
            0x4c => {
                ensure_remaining(&cursor, script.len(), 1)?;
                Some(cursor.read_u8()? as usize)
            } // 1,
            0x4d => {
                ensure_remaining(&cursor, script.len(), 2)?;
                Some(cursor.read_u16::<LittleEndian>()? as usize)
            } // 2,
            0x4e => {
                ensure_remaining(&cursor, script.len(), 4)?;
                Some(cursor.read_u32::<LittleEndian>()? as usize)
            } // 4,
            _ => None,
        };
        if let Some(len) = push_len {
            let start = cursor.position() as usize;
            let end = start + len;
            if end > script.len() {
                return Err(DecodeScriptSigError::PushLengthTooLarge {
                    len,
                    max: script.len() - start,
                });
            }
            elements.push(ScriptElement::Push {
                opcode,
                data: &script[start..end],
            });

            cursor.set_position(end as u64);
        } else {
            elements.push(ScriptElement::Op { opcode });
        }
    }

    Ok(elements)
}

fn decode_script_sig<'a>(script: &'a [u8]) -> Result<String, DecodeScriptSigError> {
    let elements = parse_script(script)?;
    Ok(script_elements_to_asm(&elements)?)
}

fn script_elements_to_asm(elements: &[ScriptElement<'_>]) -> Result<String, std::fmt::Error> {
    let mut asm = String::new();

    for (i, element) in elements.iter().enumerate() {
        if i > 0 {
            asm.push(' ');
        }
        match element {
            ScriptElement::Op { opcode } => {
                write!(asm, "{}", opcode_name(*opcode))?;
            }
            ScriptElement::Push {
                opcode: opcode @ 0x01..=0x4b,
                data,
            } => {
                write!(asm, "OP_PUSHBYTES_{} {}", *opcode, hex::encode(data))?;
            }

            ScriptElement::Push { opcode, data } => {
                write!(asm, "{} {}", opcode_name(*opcode), hex::encode(data))?;
            }
        }
    }
    Ok(asm)
}

fn ensure_remaining(
    cursor: &Cursor<&[u8]>,
    script_len: usize,
    needed: usize,
) -> Result<(), DecodeScriptSigError> {
    let remaining = script_len - cursor.position() as usize;

    if remaining < needed {
        return Err(DecodeScriptSigError::UnexpectedEof { needed, remaining });
    }
    Ok(())
}
