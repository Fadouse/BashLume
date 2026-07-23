// SPDX-License-Identifier: GPL-2.0-or-later

//! Versioned, pure-data completion rule packs and their bounded Rust VM.
//!
//! Source-shell completion scripts are build-time inputs in separate rule
//! repositories. BashLume only opens validated `.blp` artifacts at runtime.

pub mod format;
pub mod ir;
pub mod loader;
pub mod probe;
pub mod vm;
