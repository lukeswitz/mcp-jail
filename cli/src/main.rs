#![deny(unsafe_op_in_unsafe_fn)]

mod audit;
mod canonical;
mod cli;
mod commands;
mod errors;
mod sandbox;
mod store;
mod wrap;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    if let Err(e) = commands::dispatch(cli.command) {
        eprintln!("mcp-jail: {e:#}");
        std::process::exit(1);
    }
}
