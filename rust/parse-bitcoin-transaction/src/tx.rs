use crate::reader::Reader;
use std::io;

#[derive(Default, Debug)]
pub struct TxIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Default, Debug)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    /// parse
    /// Returns io::Result because
    pub fn parse(raw_tx: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(raw_tx);
        let b1 = r.read_u8();
        println!("first byte is {:?}", b1);
        Ok(Transaction::default())
    }
}
