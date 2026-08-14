use crate::libs::utils::{read_varint, txid_hex};
use crate::libs::{
    input::{read_input, DecodeScriptSigError, TxIn, TxInView},
    output::{read_output, DecodeScriptError, TxOut, TxOutView},
};
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use serde::Serialize;

use std::error::Error;
use std::fmt::Display;
use std::io::{self, Cursor};

#[derive(Default, Debug, Serialize)]
pub struct Transaction {
    pub txid: String,
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    /// parse
    pub fn parse(raw_tx: &[u8]) -> io::Result<Transaction> {
        let mut r = Cursor::new(raw_tx);
        let version = r.read_u32::<LittleEndian>()?;
        let n_inputs = read_varint(&mut r)?;
        let mut inputs: Vec<TxIn> = Vec::new();
        for _ in 0..n_inputs {
            let tx_in: TxIn = read_input(&mut r)?;
            inputs.push(tx_in);
        }
        let n_outputs = read_varint(&mut r)?;
        let mut outputs: Vec<TxOut> = Vec::new();
        for _ in 0..n_outputs {
            let tx_out: TxOut = read_output(&mut r)?;
            outputs.push(tx_out);
        }
        let txid = txid_hex(raw_tx);

        Ok(Transaction {
            txid,
            version,
            inputs,
            outputs,
            locktime: 0,
        })
    }
}

#[derive(Serialize)]
pub struct TransactionView<'a> {
    pub txid: String,
    pub version: u32,
    pub inputs: Vec<TxInView<'a>>,
    pub outputs: Vec<TxOutView<'a>>,
    pub locktime: u32,
}

#[derive(Debug)]
pub enum TransactionViewError {
    DecodeOutputScript(DecodeScriptError),
    DecodeInputScript(DecodeScriptSigError),
}

impl Display for TransactionViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionViewError::DecodeOutputScript(e) => {
                write!(f, "error decoding output script: {e}")
            }
            TransactionViewError::DecodeInputScript(e) => {
                write!(f, "error decoding input script sig: {e}")
            }
        }
    }
}

impl Error for TransactionViewError {}

impl From<DecodeScriptError> for TransactionViewError {
    fn from(error: DecodeScriptError) -> Self {
        TransactionViewError::DecodeOutputScript(error)
    }
}

impl From<DecodeScriptSigError> for TransactionViewError {
    fn from(error: DecodeScriptSigError) -> Self {
        TransactionViewError::DecodeInputScript(error)
    }
}

impl<'a> TryFrom<&'a Transaction> for TransactionView<'a> {
    type Error = TransactionViewError;
    fn try_from(tx: &'a Transaction) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            txid: tx.txid.to_owned(),
            version: tx.version,
            outputs: tx.outputs.iter().map(TxOutView::from).collect(),
            locktime: tx.locktime,
            inputs: tx.inputs.iter().map(TxInView::from).collect(),
        })
    }
}
