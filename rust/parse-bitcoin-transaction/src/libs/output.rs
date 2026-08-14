#![allow(unused)]
use crate::libs::utils::{double_hash, double_hash2, read_varint};
use bech32::{segwit, Fe32, Hrp};
use byteorder::ReadBytesExt;
use std::fmt::{Display, Write};
use std::io::{self, Cursor, Read};

use crate::libs::utils::serialize_as_hex;
use byteorder::LittleEndian;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Address(String);

impl Address {
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptPubkey(Vec<u8>);

impl AsRef<[u8]> for ScriptPubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ScriptPubkey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for ScriptPubkey {
    fn from(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }
}

impl ScriptPubkey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Default, Debug, Serialize)]
pub struct TxOut {
    pub value_sats: u64,
    pub script_pubkey: ScriptPubkey,
}

#[derive(Debug, Serialize)]
pub struct TxOutView<'a> {
    pub value_sats: u64,
    #[serde(serialize_with = "serialize_as_hex")]
    pub script_pubkey: &'a ScriptPubkey,
    pub script_pubkey_asm: Option<String>,
    pub script_pubkey_type: ScriptType,
    pub script_pubkey_address: Option<Address>,
}

impl<'a> From<&'a TxOut> for TxOutView<'a> {
    fn from(tx_out: &'a TxOut) -> Self {
        let script_view_data = build_script_view_data(&tx_out.script_pubkey, Network::Mainnet);
        Self {
            value_sats: tx_out.value_sats,
            script_pubkey: &tx_out.script_pubkey,
            script_pubkey_asm: script_view_data.asm,
            script_pubkey_type: script_view_data.script_type,
            script_pubkey_address: script_view_data.address,
        }
    }
}

#[derive(Debug)]
struct ScriptViewData {
    asm: Option<String>,
    script_type: ScriptType,
    address: Option<Address>,
}

fn build_script_view_data(script: &ScriptPubkey, network: Network) -> ScriptViewData {
    let parsed = ParsedScript::parse(script.as_ref());
    ScriptViewData {
        asm: decode_output_script_to_asm(script).ok(),
        script_type: parsed.script_type(),
        address: parsed.script_address(network),
    }
}

#[derive(Debug)]
pub enum DecodeScriptError {
    Io(std::io::Error),
    Fmt(std::fmt::Error),
    // InvalidOpcode(u8),
    // UnexpectedEof,
}

impl std::error::Error for DecodeScriptError {}

impl Display for DecodeScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeScriptError::Io(error) => write!(f, "io error while decoding script: {error}"),
            DecodeScriptError::Fmt(error) => write!(f, "io error while formatting script: {error}"),
            // DecodeScriptError::InvalidOpcode(c) => write!(f, "invalid opcode: {c:#x}"),
            // DecodeScriptError::UnexpectedEof => write!(f, "unexpected end of script"),
        }
    }
}

impl From<std::fmt::Error> for DecodeScriptError {
    fn from(err: std::fmt::Error) -> Self {
        DecodeScriptError::Fmt(err)
    }
}

impl From<std::io::Error> for DecodeScriptError {
    fn from(err: std::io::Error) -> Self {
        DecodeScriptError::Io(err)
    }
}

fn decode_output_script_to_asm(output_script: &ScriptPubkey) -> Result<String, DecodeScriptError> {
    let mut cursor = Cursor::new(output_script.as_slice());
    let mut asm = String::new();

    let mut hashed_script_len_byte: bool = false;
    let mut first = true;
    while (cursor.position() as usize) < output_script.0.len() {
        if !first {
            asm.push(' ');
        }
        first = false;
        let opcode = cursor.read_u8()?;
        if opcode == 0xa9 {
            hashed_script_len_byte = true;
        }

        if hashed_script_len_byte && (0x01..0x4b).contains(&opcode) {
            write!(asm, "OP_PUSHBYTES_{} ", opcode)?;

            let start = cursor.position() as usize;
            let len = opcode as usize;
            let end = start + len;
            write!(
                asm,
                "{}",
                hex::encode(&output_script.as_slice()[start..end])
            )?;
            cursor.set_position(end as u64);

            continue;
        }
        write!(asm, "{}", opcode_name(opcode))?;
    }

    Ok(asm)
}

pub fn read_output<R: Read>(r: &mut R) -> io::Result<TxOut> {
    const MAX_SCRIPT_SIZE: usize = 10_000;
    let value_sats = r.read_u64::<LittleEndian>()?;

    let script_length = usize::try_from(read_varint(r)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "script length does not fit in usize",
        )
    })?;
    if script_length > MAX_SCRIPT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "script pubkey too large",
        ));
    }
    let mut script_pubkey = vec![0u8; script_length];
    r.read_exact(&mut script_pubkey)?;

    Ok(TxOut {
        value_sats,
        script_pubkey: ScriptPubkey(script_pubkey),
    })
}

#[derive(Debug)]
struct DecodedOutputScript {
    asm: String,
    script_type: ScriptType,
    address: Address,
}

/// ScriptType is a representation of possible Bitcoin script types.
/// P2pkh: 76,a9,14,<20>,88, ac
/// P2sh: a9, 14,<20>,87
/// P2wpkh: 00,14,<20> (len == 22)
/// P2wsh: 00,20,<32> (len == 32)
/// P2tr: 51,20,<32> (len == 32)
/// scriptType returns the script type
#[derive(Debug, PartialEq, Serialize)]
pub enum ScriptType {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    OpReturn,
    Unknown,
}

impl Display for ScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptType::P2pkh => write!(f, "p2pkh"),
            ScriptType::P2sh => write!(f, "p2sh"),
            ScriptType::P2wpkh => write!(f, "p2wpkh"),
            ScriptType::P2wsh => write!(f, "p2wsh"),
            ScriptType::P2tr => write!(f, "p2tr"),
            ScriptType::OpReturn => write!(f, "op_return"),
            ScriptType::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyAddressType {
    P2pkh,
    P2sh,
}

#[derive(Debug)]
enum ParsedScript<'a> {
    P2pkh(&'a [u8; 20]),
    P2sh(&'a [u8; 20]),
    P2wpkh(&'a [u8; 20]),
    P2wsh(&'a [u8; 32]),
    P2tr(&'a [u8; 32]),
    OpReturn(&'a [u8]),
    Unknown,
}

impl<'a> ParsedScript<'a> {
    /// Parses a scriptPubKey into a structured borrowed view.
    fn parse(script: &'a [u8]) -> Self {
        match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
                Self::P2pkh(hash.try_into().unwrap())
            }
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
                Self::P2sh(hash.try_into().unwrap())
            }
            [0x00, 0x14, prog @ ..] if prog.len() == 20 => Self::P2wpkh(prog.try_into().unwrap()),
            [0x00, 0x20, prog @ ..] if prog.len() == 32 => Self::P2wsh(prog.try_into().unwrap()),
            [0x51, 0x20, key @ ..] if key.len() == 32 => Self::P2tr(key.try_into().unwrap()),
            [0x6a, data @ ..] => Self::OpReturn(data), //TODO: possibly this should be a decoded OP_RETURN payload?
            _ => Self::Unknown,
        }
    }

    fn script_type(&self) -> ScriptType {
        match self {
            Self::P2pkh(_) => ScriptType::P2pkh,
            Self::P2sh(_) => ScriptType::P2sh,
            Self::P2wpkh(_) => ScriptType::P2wpkh,
            Self::P2wsh(_) => ScriptType::P2wsh,
            Self::P2tr(_) => ScriptType::P2tr,
            Self::OpReturn(_) => ScriptType::OpReturn,
            Self::Unknown => ScriptType::Unknown,
        }
    }

    fn script_address(&self, network: Network) -> Option<Address> {
        match *self {
            Self::P2pkh(hash) => Some(encode_legacy_address(
                hash,
                network,
                LegacyAddressType::P2pkh,
            )),
            Self::P2sh(hash) => Some(encode_legacy_address(
                hash,
                network,
                LegacyAddressType::P2sh,
            )),
            Self::P2wpkh(prog) => bech32_address(prog, network, Fe32::Q),
            Self::P2wsh(prog) => bech32_address(prog, network, Fe32::Q),
            Self::P2tr(prog) => bech32_address(prog, network, Fe32::P),
            Self::OpReturn(_) | Self::Unknown => None,
        }
    }
}

/// Helper function extracts the script type based on the provided script bytes
fn extract_script_type<T: AsRef<[u8]>>(script: T) -> ScriptType {
    ParsedScript::parse(script.as_ref()).script_type()
}

/// Helper function reports the address for the script/network combination
fn extract_address<T: AsRef<[u8]>>(script: T, network: Network) -> Option<Address> {
    ParsedScript::parse(script.as_ref()).script_address(network)
}

/// Derive a bech32 address;
/// witness_version 0 == Fe32::Q
/// witness_version 1 == Fe32::P
fn bech32_address(prog: &[u8], network: Network, witness_version: Fe32) -> Option<Address> {
    let hrp = match network {
        Network::Mainnet => "bc",
        Network::Testnet | Network::Signet => "tb",
        Network::Regtest => "bcrt",
    };

    let addr = segwit::encode(Hrp::parse_unchecked(hrp), witness_version, prog).ok()?;
    Some(Address::new_unchecked(addr))
}

fn encode_legacy_address(
    hash: &[u8; 20],
    network: Network,
    address_type: LegacyAddressType,
) -> Address {
    let prefix = legacy_prefix(network, address_type);

    let mut payload = [0u8; 21];
    payload[0] = prefix;
    payload[1..].copy_from_slice(hash);

    let digest = double_hash(&payload);

    let mut out = [0u8; 25]; // Prefix (1 byte) | hash (20 bytes) | checksum (4 bytes)
    out[..21].copy_from_slice(&payload);
    out[21..].copy_from_slice(&digest[..4]);

    // FIXME: check this!! Is there a better way of getting encode() output into an Address?
    Address::new_unchecked(bs58::encode(out).into_string())
}

fn legacy_prefix(network: Network, address_type: LegacyAddressType) -> u8 {
    match (network, address_type) {
        (Network::Mainnet, LegacyAddressType::P2pkh) => 0x00,
        (Network::Mainnet, LegacyAddressType::P2sh) => 0x05,

        (Network::Testnet, LegacyAddressType::P2pkh)
        | (Network::Signet, LegacyAddressType::P2pkh)
        | (Network::Regtest, LegacyAddressType::P2pkh) => 0x6f,

        (Network::Testnet, LegacyAddressType::P2sh)
        | (Network::Signet, LegacyAddressType::P2sh)
        | (Network::Regtest, LegacyAddressType::P2sh) => 0xc4,
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "OP_0",         // Push empty / false
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

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::primitives::gf32::Fe32;

    #[test]
    fn bech32_address_encodes_known_valid_vectors() {
        // BIP-173 mainnet P2WPKH:
        // scriptPubKey = 0014751e76e8199196d454941c45d1b3a323f1433bd6
        // witness program = 751e76e8199196d454941c45d1b3a323f1433bd6
        let p2wpkh_prog: [u8; 20] = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];

        let addr = bech32_address(&p2wpkh_prog, Network::Mainnet, Fe32::Q)
            .expect("v0 P2WPKH address should encode");
        assert_eq!(addr.as_ref(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        // BIP-173 testnet P2WSH:
        // scriptPubKey = 00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
        // witness program = 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
        let p2wsh_prog: [u8; 32] = [
            0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56,
            0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96,
            0x04, 0x90, 0x32, 0x62,
        ];

        let addr = bech32_address(&p2wsh_prog, Network::Testnet, Fe32::Q)
            .expect("v0 P2WSH address should encode");
        assert_eq!(
            addr.as_ref(),
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
        );

        // BIP-350 mainnet v1 / Taproot-style example:
        // scriptPubKey = 512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        // witness program = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        let p2tr_prog: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];

        let addr = bech32_address(&p2tr_prog, Network::Mainnet, Fe32::P)
            .expect("v1 P2TR address should encode");
        assert_eq!(
            addr.as_ref(),
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        );
    }

    #[test]
    fn bech32_address_rejects_invalid_program_lengths() {
        // Witness v0 is only valid for 20-byte and 32-byte programs.
        let bad_v0_prog = [0u8; 21];
        assert!(bech32_address(&bad_v0_prog, Network::Mainnet, Fe32::Q).is_none());

        // Witness program length must be between 2 and 40 bytes inclusive.
        let bad_v1_prog = [0u8; 41];
        assert!(bech32_address(&bad_v1_prog, Network::Mainnet, Fe32::P).is_none());
    }
}
