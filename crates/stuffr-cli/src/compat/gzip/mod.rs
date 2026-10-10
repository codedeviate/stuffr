//! The gzip compatibility family (`gzip`, `gunzip`, `zcat`, ...).
//!
//! Only the member layer exists so far; the personalities, sniffing and
//! dispatch land in later tasks.
#![allow(dead_code)] // wired into dispatch in Task 7

pub(crate) mod member;
pub(crate) mod sniff;
