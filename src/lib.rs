// SPDX-License-Identifier: GPL-3.0-or-later

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod auth;
pub mod client;
pub mod config;
pub mod consts;
pub mod error;
pub mod policy;
pub mod secret;
pub mod tls;

pub use client::{ApiResponse, Client, ClientBuilder, PreparedRequest};
pub use error::{Error, Result};
pub use policy::{RetryPolicy, Timeouts};
pub use secret::{ApiKey, ApiSecret};
pub use tls::TlsMode;
