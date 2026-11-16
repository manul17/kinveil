//! Local encrypted control plane, config renderer, and SSH deployer for Kinveil VPN servers.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("kinveil requires a Unix host OS (Linux or macOS)");

pub mod cli;
pub mod crypto;
pub mod deploy;
pub mod render;
pub mod state;
pub mod store;
pub mod validate;
