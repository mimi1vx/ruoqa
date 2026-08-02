// SPDX-License-Identifier: GPL-3.0-or-later

pub mod error;
pub mod secret;

pub use error::{Error, Result};
pub use secret::{ApiKey, ApiSecret};
