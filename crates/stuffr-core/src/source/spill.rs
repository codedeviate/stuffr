//! Rung 3 of the ladder: spool a non-seekable input so it becomes seekable.
//!
//! Spilling costs disk and latency, never accuracy — which is why
//! [`crate::Rung::Spilled`] counts as authoritative.

use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;

use super::{GuardedSeek, SeekRead, Source, SourceCaps};
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

    /// How many bytes this policy holds in memory before it escalates (or,
    /// for `Memory`, fails): `0` for `Off`.
    pub fn memory_cap(&self) -> u64 {
        match self {
            SpillPolicy::Off => 0,
            SpillPolicy::Memory { cap } => *cap,
            SpillPolicy::Temp { mem_cap, .. } => *mem_cap,
        }
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
    Mem(GuardedSeek<Cursor<Vec<u8>>>),
    File(GuardedSeek<std::fs::File>),
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
        Self::materialize_from(&mut *src, policy)
    }

    /// [`Self::materialize`] from any reader, borrowed: for a caller whose
    /// bytes are not a [`Source`] — an archive entry's payload borrows its
    /// archive, so it can be neither boxed as `'static` nor sent. `stuffr
    /// convert` buffers an entry of unknown size through this, under the same
    /// policy. The limits are [`SpillWriter`]'s, which this drives.
    pub fn materialize_from<R: Read + ?Sized>(src: &mut R, policy: &SpillPolicy) -> Result<Self> {
        let mut spool = SpillWriter::new(policy)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                return spool.finish();
            }
            spool.push(&buf[..n])?;
        }
    }

    /// Whether the spool escalated past the memory cap. Surfaced by `stuffr info`.
    pub fn spilled_to_disk(&self) -> bool {
        self.on_disk
    }
}

/// The push side of the spill loop: bytes handed over one slice at a time,
/// held in memory up to the policy's memory cap, then in a temp file, and
/// refused past its hard limit. The one owner of those limits —
/// [`SpillSource::materialize_from`] drives it from a reader, and a caller
/// that sees the bytes go past on their way somewhere else (a tee) pushes
/// them itself.
///
/// A refusal ([`Error::SpillLimitExceeded`]) or a temp-file failure leaves
/// the writer unusable; nothing it held is ever handed out partially.
#[derive(Debug)]
pub struct SpillWriter {
    limit: u64,
    mem_cap: u64,
    dir: Option<Option<PathBuf>>,
    mem: Vec<u8>,
    file: Option<std::fs::File>,
    total: u64,
}

impl SpillWriter {
    /// An empty spool under `policy`. `SpillPolicy::Off` is refused at once,
    /// as [`SpillSource::materialize`] refuses it.
    pub fn new(policy: &SpillPolicy) -> Result<Self> {
        if !policy.is_enabled() {
            return Err(Error::SpillLimitExceeded { limit: 0 });
        }
        Ok(Self {
            limit: policy.hard_limit(),
            mem_cap: policy.memory_cap(),
            dir: match policy {
                SpillPolicy::Temp { dir, .. } => Some(dir.clone()),
                SpillPolicy::Off | SpillPolicy::Memory { .. } => None,
            },
            mem: Vec::new(),
            file: None,
            total: 0,
        })
    }

    /// Bytes accepted so far.
    pub fn len(&self) -> u64 {
        self.total
    }

    /// Whether nothing has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Appends `bytes`, escalating to a temp file once the memory cap is
    /// passed, and refusing past the hard limit.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.total += bytes.len() as u64;
        if self.total > self.limit {
            return Err(Error::SpillLimitExceeded { limit: self.limit });
        }
        if let Some(file) = &mut self.file {
            file.write_all(bytes)?;
            return Ok(());
        }
        if self.total <= self.mem_cap {
            self.mem.extend_from_slice(bytes);
            return Ok(());
        }
        // Past the memory cap. Defensive for `Memory`, unreachable while
        // `mem_cap == hard_limit()` holds for it: the limit check above
        // always fires first.
        let Some(dir) = &self.dir else {
            return Err(Error::SpillLimitExceeded { limit: self.limit });
        };
        let mut file = match dir {
            Some(d) => tempfile::tempfile_in(d)?,
            None => tempfile::tempfile()?,
        };
        file.write_all(&self.mem)?;
        file.write_all(bytes)?;
        self.mem = Vec::new();
        self.file = Some(file);
        Ok(())
    }

    /// The bytes pushed, as a seekable source positioned at the start.
    pub fn finish(self) -> Result<SpillSource> {
        match self.file {
            None => Ok(SpillSource {
                backing: Backing::Mem(GuardedSeek::new(Cursor::new(self.mem))),
                len: self.total,
                on_disk: false,
            }),
            Some(mut file) => {
                file.flush()?;
                file.seek(std::io::SeekFrom::Start(0))?;
                Ok(SpillSource {
                    backing: Backing::File(GuardedSeek::new(file)),
                    len: self.total,
                    on_disk: true,
                })
            }
        }
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

    /// The push side keeps the pull side's limits: memory up to the cap,
    /// then a temp file holding every byte in order, refused past the max.
    #[test]
    fn a_spill_writer_escalates_and_refuses_like_materialize() {
        let policy = SpillPolicy::Temp {
            dir: None,
            mem_cap: 10,
            max: 30,
        };
        let mut w = SpillWriter::new(&policy).unwrap();
        w.push(b"0123456789").unwrap();
        w.push(b"abcdef").unwrap();
        assert_eq!(w.len(), 16);
        let mut s = w.finish().unwrap();
        assert!(s.spilled_to_disk());
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"0123456789abcdef");

        let mut w = SpillWriter::new(&policy).unwrap();
        let err = w.push(&[0u8; 31]).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::SpillLimitExceeded { limit: 30 }
        ));
        assert!(matches!(
            SpillWriter::new(&SpillPolicy::Off).unwrap_err(),
            crate::Error::SpillLimitExceeded { limit: 0 }
        ));
        assert_eq!(policy.memory_cap(), 10);
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
