mod reader;
mod script;
mod tx;
use crate::tx::Transaction;
use std::process;

use clap::Parser;
///
/// Simple CLI that requires a --pubkey argument
#[derive(Parser, Debug)]
#[command(version, about = "Takes a required --tx argument", long_about = None)]
struct Args {
    /// The public key (required)
    #[arg(long, required = true)]
    tx: String,
}

fn main() {
    let args = Args::parse();
    let input_tx = args.tx;
    let raw_tx = match hex::decode(&input_tx) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to decode hex from {}: {}", input_tx, e);
            process::exit(1);
        }
    };

    let tx = match Transaction::parse(&raw_tx) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("failed to parse tx {}: {}", input_tx, e);
            process::exit(1);
        }
    };
    println!("{:?}", tx)
}
