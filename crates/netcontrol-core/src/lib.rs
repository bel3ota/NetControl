//! NetControl shared core.
//!
//! This crate has no privilege-dependent behaviour: discovery, gateway
//! adapters, the management service and every UI consume these types. That
//! keeps device identity, persistence, audit semantics and security rules
//! identical across Windows, Linux and Android-adjacent management clients.

pub mod classify;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod oui;
pub mod security;
pub mod util;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PRODUCT_NAME: &str = "NetControl";
