mod libs;
use crate::libs::tx::{Transaction, TransactionView};

use clap::Parser;
use color_eyre::eyre::{Context, Ok};
use color_eyre::Result;
use tracing::instrument;
use tracing_error::ErrorLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Arguments for a simple CLI that requires a --tx argument
#[derive(Parser, Debug)]
#[command(version, about = "Takes a required --tx argument", long_about = None)]
struct Args {
    #[arg(long, required = true)]
    tx: String,
}

#[instrument(skip_all)]
fn run() -> Result<()> {
    let args = Args::parse();
    let tx = decode_and_parse(&args.tx)?;

    let display_tx = TransactionView::try_from(&tx)?;
    let json = serde_json::to_string(&display_tx).context("failed to serialize to JSON")?;
    println!("{}", json);
    Ok(())
}

fn decode_and_parse(input_tx: &str) -> Result<Transaction> {
    let raw_tx =
        hex::decode(input_tx).with_context(|| format!("failed to decode hex from {}", input_tx))?;
    let tx = Transaction::parse(&raw_tx).context("failed to parse tx bytes")?;
    Ok(tx)
}

fn install_tracing() -> Result<()> {
    let fmt_layer = fmt::layer().with_target(false);

    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .try_init()?;

    Ok(())
}

fn install_error_hooks() -> Result<()> {
    color_eyre::install()?;
    Ok(())
}

fn main() -> Result<()> {
    install_tracing()?;
    install_error_hooks()?;
    run()
}
