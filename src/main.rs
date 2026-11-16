#![forbid(unsafe_code)]

use clap::Parser;

use kinveil::cli::{Cli, run_cli};

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run_cli(cli) {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
