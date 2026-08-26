//! Rung 3 of the ladder: spool a non-seekable input so it becomes seekable.
//!
//! Spilling costs disk and latency, never accuracy — which is why
//! [`crate::Rung::Spilled`] counts as authoritative.

use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;

use super::{SeekRead, Source, SourceCaps};
use crate::error::{Error, Result};

pub const DEFAULT_MEM_CAP: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_SPILL: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SpillPolicy {
    /// Never spool. Collapses the ladder from four rungs to three.
    Off,
    /// Spool in memory only, failing past `cap`.
    Memory { cap: u64 },
    /// Spool in memory up to `mem_cap`, then escalate to a temp file, failing
    /// past `max`.
    Temp {
        dir: Option<PathBuf>,
        mem_cap: u64,
        max: u64,
    },
}

impl Default for SpillPolicy {
    fn default() -> Self {
        SpillPolicy::Temp {
            dir: None,
            mem_cap: DEFAULT_MEM_CAP,
            max: DEFAULT_MAX_SPILL,
        }
    }
}

impl SpillPolicy {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, SpillPolicy::Off)
    }

    fn hard_limit(&self) -> u64 {
        match self {
            SpillPolicy::Off => 0,
            SpillPolicy::Memory { cap } => *cap,
            SpillPolicy::Temp { max, .. } => *max,
        }
    }
}

#[derive(Debug)]
enum Backing {
    Mem(Cursor<Vec<u8>>),
    File(std::fs::File),
}

/// A seekable source produced by draining a forward-only one.
#[derive(Debug)]
pub struct SpillSource {
    backing: Backing,
    len: u64,
    on_disk: bool,
}

impl SpillSource {
    /// Drains `src` into a seekable backing store, eagerly.
    ///
    /// Eager rather than lazy: a container that asked for seek is about to read
    /// the trailing index, so it will need the whole stream regardless, and the
    /// eager path has no partially-materialized states to get wrong.
    pub fn materialize(mut src: Box<dyn Source>, policy: &SpillPolicy) -> Result<Self> {
        let limit = policy.hard_limit();
        if !policy.is_enabled() {
            return Err(Error::SpillLimitExceeded { limit: 0 });
        }

        let mem_cap = match policy {
            SpillPolicy::Off => 0,
            SpillPolicy::Memory { cap } => *cap,
            SpillPolicy::Temp { mem_cap, .. } => *mem_cap,
        };

        let mut mem: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;

        // Phase 1: fill memory up to mem_cap.
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                return Ok(Self {
                    len: total,
                    backing: Backing::Mem(Cursor::new(mem)),
                    on_disk: false,
                });
            }
            total += n as u64;
            if total > limit {
                return Err(Error::SpillLimitExceeded { limit });
            }
            if total > mem_cap {
                mem.extend_from_slice(&buf[..n]);
                break;
            }
            mem.extend_from_slice(&buf[..n]);
        }

        // Phase 2: escalate to a temp file, carrying the memory buffer over.
        let SpillPolicy::Temp { dir, .. } = policy else {
            // Defensive, unreachable while `mem_cap == hard_limit()` holds for
            // `Memory`: the `total > limit` check above always fires first, so
            // the Phase-1 loop never breaks into this arm for that policy.
            return Err(Error::SpillLimitExceeded { limit });
        };

        let mut file = match dir {
            Some(d) => tempfile::tempfile_in(d)?,
            None => tempfile::tempfile()?,
        };
        file.write_all(&mem)?;
        drop(mem);

        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > limit {
                return Err(Error::SpillLimitExceeded { limit });
            }
            file.write_all(&buf[..n])?;
        }

        file.flush()?;
        file.seek(std::io::SeekFrom::Start(0))?;
        Ok(Self {
            backing: Backing::File(file),
            len: total,
            on_disk: true,
        })
    }

    /// Whether the spool escalated past the memory cap. Surfaced by `stf info`.
    pub fn spilled_to_disk(&self) -> bool {
        self.on_disk
    }
}

impl Read for SpillSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.backing {
            Backing::Mem(c) => c.read(buf),
            Backing::File(f) => f.read(buf),
        }
    }
}

impl Source for SpillSource {
    fn caps(&self) -> SourceCaps {
        SourceCaps {
            seekable: true,
            len: Some(self.len),
        }
    }

    fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
        match &mut self.backing {
            Backing::Mem(c) => Some(c),
            Backing::File(f) => Some(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::source::ReaderSource;
    use std::io::{Read, SeekFrom};

    use super::*;

    fn pipe(bytes: Vec<u8>) -> Box<dyn crate::source::Source> {
        Box::new(ReaderSource::new(std::io::Cursor::new(bytes)))
    }

    #[test]
    fn small_input_stays_in_memory_and_becomes_seekable() {
        let mut s = SpillSource::materialize(
            pipe(b"0123456789".to_vec()),
            &SpillPolicy::Temp {
                dir: None,
                mem_cap: 1024,
                max: 1 << 20,
            },
        )
        .unwrap();

        assert!(!s.spilled_to_disk());
        assert!(s.caps().seekable);
        assert_eq!(s.caps().len, Some(10));

        let seek = s.as_seek().unwrap();
        seek.seek(SeekFrom::Start(7)).unwrap();
        let mut buf = [0u8; 3];
        seek.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"789");
    }

    #[test]
    fn input_over_the_memory_cap_escalates_to_a_temp_file() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut s = SpillSource::materialize(
            pipe(data.clone()),
            &SpillPolicy::Temp {
                dir: None,
                mem_cap: 64,
                max: 1 << 20,
            },
        )
        .unwrap();

        assert!(s.spilled_to_disk());
        assert_eq!(s.caps().len, Some(4096));

        // Escalation must not lose or reorder the bytes already buffered.
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn memory_only_policy_refuses_to_exceed_its_cap() {
        let err = SpillSource::materialize(pipe(vec![7u8; 500]), &SpillPolicy::Memory { cap: 100 })
            .unwrap_err();

        // Never a silent truncation: a stream too big to spool must say so.
        assert!(matches!(
            err,
            crate::Error::SpillLimitExceeded { limit: 100 }
        ));
        assert_eq!(err.exit_code(), 6);
    }

    #[test]
    fn max_spill_is_enforced_for_the_temp_policy_too() {
        let err = SpillSource::materialize(
            pipe(vec![7u8; 5000]),
            &SpillPolicy::Temp {
                dir: None,
                mem_cap: 16,
                max: 1000,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::SpillLimitExceeded { limit: 1000 }
        ));
    }

    #[test]
    fn off_policy_is_not_enabled_and_cannot_materialize() {
        assert!(!SpillPolicy::Off.is_enabled());
        assert!(SpillPolicy::default().is_enabled());
        let err = SpillSource::materialize(pipe(b"x".to_vec()), &SpillPolicy::Off).unwrap_err();
        assert!(matches!(err, crate::Error::SpillLimitExceeded { limit: 0 }));
    }

    #[test]
    fn defaults_match_the_spec() {
        match SpillPolicy::default() {
            SpillPolicy::Temp { mem_cap, max, dir } => {
                assert_eq!(mem_cap, 64 * 1024 * 1024);
                assert_eq!(max, 2 * 1024 * 1024 * 1024);
                assert!(dir.is_none());
            }
            other => panic!("unexpected default: {other:?}"),
        }
    }

    #[test]
    fn empty_input_materializes_to_an_empty_seekable_source() {
        let mut s = SpillSource::materialize(pipe(Vec::new()), &SpillPolicy::default()).unwrap();
        assert_eq!(s.caps().len, Some(0));
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn escalation_preserves_order_across_many_sub_cap_chunks() {
        // A Cursor hands over the whole input in one read, so the multi-chunk
        // accumulate-then-escalate path never runs. Force 100-byte reads so the
        // memory buffer genuinely grows across several iterations before the
        // temp file takes over.
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let src: Box<dyn Source> = Box::new(crate::source::ReaderSource::new(
            crate::testing::ChunkedReader::new(data.clone(), 100),
        ));
        let mut s = SpillSource::materialize(
            src,
            &SpillPolicy::Temp {
                dir: None,
                mem_cap: 1000,
                max: 1 << 20,
            },
        )
        .unwrap();

        assert!(s.spilled_to_disk());
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, data, "bytes must survive escalation in order");
    }
}
