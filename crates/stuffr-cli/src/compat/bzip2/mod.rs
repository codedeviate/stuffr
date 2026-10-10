//! The `bzip2` / `bunzip2` / `bzcat` family. A stub until the real entry
//! point replaces it.

use std::ffi::OsString;
use std::process::ExitCode;

use super::Prog;

/// Entry point for the bzip2 family; `name` is the canonical invoked name.
pub fn run(name: &'static str, _args: Vec<OsString>) -> ExitCode {
    Prog { name }.err(format_args!("not yet implemented"));
    ExitCode::from(3)
}
