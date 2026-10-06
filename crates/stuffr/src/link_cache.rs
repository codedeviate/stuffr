//! The payloads `convert` and `cat` keep so a later hard link can be written
//! as a copy of its target's bytes.
//!
//! A `Hardlink` entry's own reader yields nothing; its content is an EARLIER
//! entry's. Into a container that cannot store links (`!stores_hardlinks`),
//! and for `cat`, the only bytes that can be written for one are that
//! earlier payload, read once already and kept here. What is kept, and how
//! much, depends on what the source can say in advance ([`CachePolicy`]):
//!
//! - **cpio** announces the payloads later names link to
//!   ([`stuffr_core::Entry::announces_links`]), so only those are kept, under
//!   the convert's full [`SpillPolicy`]: memory, then a temp file.
//! - **tar** announces nothing, so every regular-file payload is a candidate,
//!   and it is kept in memory only, within the policy's memory tier. A temp
//!   file under a tar would spool the whole archive for a convert that holds
//!   no links at all.
//!
//! Both are bounded the same way: a payload larger than the policy is
//! declined (its write is unaffected), and older payloads are evicted, oldest
//! first, to make room for a newer one. The cache never holds more than its
//! policy allows. A link whose target is not kept is the caller's to skip
//! with a warning; nothing here ever hands out a partial or empty stand-in.
//!
//! cpio's reader emits a data-last group's links immediately after its data
//! member, so in the GNU layout the evicted payload is always one whose group
//! is complete. A data-first layout holds its payload until eviction; a link
//! arriving after that is skipped, by the same rule.

use std::collections::VecDeque;
use std::io::{Read, SeekFrom};
use std::path::PathBuf;

use stuffr_core::{EntryKind, EntryMeta, FormatId, Source, SpillPolicy, SpillSource, SpillWriter};

/// Which payloads a [`LinkCache`] keeps, and within what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CachePolicy {
    /// cpio: keep only payloads of files known to be linked, under the full
    /// spill policy (memory, then temp file).
    Announced(SpillPolicy),
    /// tar: keep recent regular-file payloads in memory only, oldest evicted
    /// first, within `cap` bytes (the spill policy's memory tier).
    Recent { cap: u64 },
    /// The target stores links itself, or the source has none: keep nothing.
    Off,
}

impl CachePolicy {
    /// What `convert` keeps: nothing into a target that `stores_hardlinks`,
    /// else what the source container can say ([`Self::for_source`]).
    pub(crate) fn for_convert(
        source: FormatId,
        target_stores_hardlinks: bool,
        spill: &SpillPolicy,
    ) -> Self {
        if target_stores_hardlinks {
            return CachePolicy::Off;
        }
        Self::for_source(source, spill)
    }

    /// cpio announces its linked payloads; tar does not; no other container
    /// in this build yields a hard link at all.
    pub(crate) fn for_source(source: FormatId, spill: &SpillPolicy) -> Self {
        match source.as_str() {
            "cpio" => CachePolicy::Announced(spill.clone()),
            "tar" => CachePolicy::Recent {
                cap: spill.memory_cap(),
            },
            _ => CachePolicy::Off,
        }
    }
}

/// The policy's bounds, flattened: `mem` bytes in memory, `total` bytes in
/// all, and a temp file only when `disk` says where (`Some(None)`: the
/// system temp dir).
struct Limits {
    mem: u64,
    total: u64,
    disk: Option<Option<PathBuf>>,
}

/// Payloads kept so a later hard link can be written as a copy.
pub(crate) struct LinkCache {
    policy: CachePolicy,
    /// Oldest first. At most one payload per name: keeping a name replaces
    /// what was kept under it.
    kept: VecDeque<(String, SpillSource)>,
    in_memory: u64,
    on_disk: u64,
}

impl LinkCache {
    pub(crate) fn new(policy: CachePolicy) -> Self {
        Self {
            policy,
            kept: VecDeque::new(),
            in_memory: 0,
            on_disk: 0,
        }
    }

    fn limits(&self) -> Option<Limits> {
        match &self.policy {
            CachePolicy::Off | CachePolicy::Announced(SpillPolicy::Off) => None,
            CachePolicy::Recent { cap } | CachePolicy::Announced(SpillPolicy::Memory { cap }) => {
                Some(Limits {
                    mem: *cap,
                    total: *cap,
                    disk: None,
                })
            }
            CachePolicy::Announced(SpillPolicy::Temp { dir, mem_cap, max }) => Some(Limits {
                mem: (*mem_cap).min(*max),
                total: *max,
                disk: Some(dir.clone()),
            }),
        }
    }

    fn held(&self) -> u64 {
        self.in_memory + self.on_disk
    }

    /// Whether this entry's payload should be kept: under `Announced`,
    /// `announces_links`; under `Recent`, any `File`; `Off`, never.
    pub(crate) fn wants(&self, meta: &EntryMeta, announces_links: bool) -> bool {
        if meta.kind != EntryKind::File || self.limits().is_none() {
            return false;
        }
        match self.policy {
            CachePolicy::Announced(_) => announces_links,
            CachePolicy::Recent { .. } => true,
            CachePolicy::Off => false,
        }
    }

    /// A spool for the payload about to be written under `name`, sized from
    /// what the policy has left once older payloads are evicted to fit
    /// `size` (when it is known). `None` when the payload cannot be kept at
    /// all: the policy is off, or `size` alone is past it.
    ///
    /// Whatever was kept under `name` before is dropped first, kept or not
    /// now: a later link to `name` means the LATEST entry of that name.
    pub(crate) fn spool(&mut self, name: &str, size: Option<u64>) -> Option<SpillWriter> {
        self.forget(name);
        let limits = self.limits()?;
        if let Some(size) = size {
            if size > limits.total {
                return None;
            }
            while self.held() + size > limits.total && self.evict_oldest() {}
        }
        let total = limits.total.saturating_sub(self.held());
        let mem = limits.mem.saturating_sub(self.in_memory).min(total);
        let policy = match limits.disk {
            None => SpillPolicy::Memory { cap: mem },
            Some(dir) => SpillPolicy::Temp {
                dir,
                mem_cap: mem,
                max: total,
            },
        };
        SpillWriter::new(&policy).ok()
    }

    /// Stores `bytes` (already read once, for the write) under `name`,
    /// evicting the oldest payloads to make room. Silently declines a
    /// payload the policy cannot hold; nothing is kept under `name` then.
    pub(crate) fn keep(&mut self, name: &str, bytes: SpillSource) {
        self.forget(name);
        let Some(limits) = self.limits() else {
            return;
        };
        let len = bytes.caps().len.unwrap_or(u64::MAX);
        let disk = bytes.spilled_to_disk();
        if len > limits.total || (disk && limits.disk.is_none()) || (!disk && len > limits.mem) {
            return;
        }
        while self.held() + len > limits.total && self.evict_oldest() {}
        while !disk && self.in_memory + len > limits.mem && self.evict_oldest() {}
        if disk {
            self.on_disk += len;
        } else {
            self.in_memory += len;
        }
        self.kept.push_back((name.to_string(), bytes));
    }

    /// Whether `target`'s bytes are kept.
    pub(crate) fn contains(&self, target: &str) -> bool {
        self.kept.iter().any(|(n, _)| n == target)
    }

    /// A fresh reader over `target`'s bytes, with their length, or `None`
    /// if not kept.
    pub(crate) fn copy_of(
        &mut self,
        target: &str,
    ) -> stuffr_core::Result<Option<(u64, Box<dyn Read + '_>)>> {
        let Some((_, bytes)) = self.kept.iter_mut().find(|(n, _)| n == target) else {
            return Ok(None);
        };
        let len = bytes.caps().len.unwrap_or(0);
        if let Some(seek) = bytes.as_seek() {
            seek.seek(SeekFrom::Start(0))?;
        }
        Ok(Some((len, Box::new(bytes))))
    }

    /// Drops whatever is kept under `name`.
    pub(crate) fn forget(&mut self, name: &str) {
        while let Some(i) = self.kept.iter().position(|(n, _)| n == name) {
            if let Some((_, bytes)) = self.kept.remove(i) {
                self.release(&bytes);
            }
        }
    }

    /// Drops the oldest payload, answering whether there was one.
    fn evict_oldest(&mut self) -> bool {
        match self.kept.pop_front() {
            Some((_, bytes)) => {
                self.release(&bytes);
                true
            }
            None => false,
        }
    }

    fn release(&mut self, bytes: &SpillSource) {
        let len = bytes.caps().len.unwrap_or(0);
        if bytes.spilled_to_disk() {
            self.on_disk -= len;
        } else {
            self.in_memory -= len;
        }
    }
}

/// A reader that hands every byte it reads to a spool as well — how a payload
/// is kept WHILE it streams into the archive, read once. A spool that refuses
/// a byte (past its policy, or a temp-file failure) is abandoned, leaving
/// `None`; the reads themselves are never affected.
pub(crate) struct Tee<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    spool: &'a mut Option<SpillWriter>,
    /// Bytes handed out, kept or not.
    pub(crate) seen: u64,
}

impl<'a, R: Read + ?Sized> Tee<'a, R> {
    pub(crate) fn new(inner: &'a mut R, spool: &'a mut Option<SpillWriter>) -> Self {
        Self {
            inner,
            spool,
            seen: 0,
        }
    }
}

impl<R: Read + ?Sized> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        if let Some(spool) = self.spool.as_mut()
            && spool.push(&buf[..n]).is_err()
        {
            *self.spool = None;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> EntryMeta {
        EntryMeta::file(name)
    }

    /// Spools `bytes` under `name` through a [`Tee`], as the convert loop
    /// does, and keeps the result if the spool survived.
    fn put(cache: &mut LinkCache, name: &str, bytes: &[u8]) {
        let mut spool = cache.spool(name, Some(bytes.len() as u64));
        let mut src = bytes;
        let mut tee = Tee::new(&mut src, &mut spool);
        let mut sink = Vec::new();
        tee.read_to_end(&mut sink).unwrap();
        assert_eq!(sink, bytes, "the tee never alters what the writer reads");
        if let Some(spool) = spool {
            cache.keep(name, spool.finish().unwrap());
        }
    }

    fn read_back(cache: &mut LinkCache, name: &str) -> Option<Vec<u8>> {
        let (len, mut r) = cache.copy_of(name).unwrap()?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out.len() as u64, len);
        Some(out)
    }

    #[test]
    fn recent_keeps_within_cap_and_evicts_oldest_first() {
        let mut cache = LinkCache::new(CachePolicy::Recent { cap: 10 });
        assert!(cache.wants(&file("a"), false));
        put(&mut cache, "a", b"aaaa");
        put(&mut cache, "b", b"bbbb");
        assert_eq!(read_back(&mut cache, "a").unwrap(), b"aaaa");
        // 4 + 4 + 4 > 10: the oldest, `a`, makes room.
        put(&mut cache, "c", b"cccc");
        assert!(!cache.contains("a"));
        assert_eq!(read_back(&mut cache, "b").unwrap(), b"bbbb");
        assert_eq!(read_back(&mut cache, "c").unwrap(), b"cccc");
        // Read twice: every copy is a fresh reader from the start.
        assert_eq!(read_back(&mut cache, "c").unwrap(), b"cccc");
        assert!(cache.held() <= 10);
    }

    #[test]
    fn a_payload_larger_than_the_cap_is_declined_not_truncated() {
        let mut cache = LinkCache::new(CachePolicy::Recent { cap: 10 });
        put(&mut cache, "small", b"ok");
        // Declared past the cap: no spool at all, and nothing evicted for it.
        assert!(cache.spool("big", Some(11)).is_none());
        assert!(cache.contains("small"));
        // Undeclared and past the cap: the tee abandons the spool mid-way.
        let mut spool = cache.spool("big", None);
        let mut src = &[7u8; 64][..];
        let mut tee = Tee::new(&mut src, &mut spool);
        std::io::copy(&mut tee, &mut std::io::sink()).unwrap();
        assert_eq!(tee.seen, 64);
        assert!(spool.is_none(), "a partial copy is never kept");
        assert!(read_back(&mut cache, "big").is_none());
        // A newer entry of a kept name that is NOT kept leaves no stale copy.
        put(&mut cache, "small", &[1u8; 11]);
        assert!(!cache.contains("small"));
        assert_eq!(cache.held(), 0);
    }

    #[test]
    fn off_keeps_nothing() {
        let mut cache = LinkCache::new(CachePolicy::Off);
        assert!(!cache.wants(&file("a"), true));
        assert!(cache.spool("a", Some(1)).is_none());
        let src = SpillSource::materialize_from(&mut &b"x"[..], &SpillPolicy::default()).unwrap();
        cache.keep("a", src);
        assert!(read_back(&mut cache, "a").is_none());
        // Off by spill policy too, and for every source but cpio and tar.
        let off = LinkCache::new(CachePolicy::Announced(SpillPolicy::Off));
        assert!(!off.wants(&file("a"), true));
        assert_eq!(
            CachePolicy::for_source(FormatId::new("zip"), &SpillPolicy::default()),
            CachePolicy::Off
        );
        assert_eq!(
            CachePolicy::for_convert(FormatId::new("cpio"), true, &SpillPolicy::default()),
            CachePolicy::Off
        );
    }

    #[test]
    fn announced_spills_past_memory_into_a_temp_file() {
        let mut cache = LinkCache::new(CachePolicy::Announced(SpillPolicy::Temp {
            dir: None,
            mem_cap: 1024,
            max: 1 << 20,
        }));
        // Only an announced file is wanted.
        assert!(!cache.wants(&file("a"), false));
        assert!(cache.wants(&file("a"), true));
        let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        put(&mut cache, "a", &payload);
        assert_eq!(cache.on_disk, 2048, "past the memory tier, on disk");
        assert_eq!(cache.in_memory, 0);
        assert_eq!(read_back(&mut cache, "a").unwrap(), payload);
    }

    #[test]
    fn the_policy_follows_the_source_container() {
        let spill = SpillPolicy::Temp {
            dir: None,
            mem_cap: 5,
            max: 50,
        };
        assert_eq!(
            CachePolicy::for_convert(FormatId::new("tar"), false, &spill),
            CachePolicy::Recent { cap: 5 }
        );
        assert_eq!(
            CachePolicy::for_convert(FormatId::new("cpio"), false, &spill),
            CachePolicy::Announced(spill.clone())
        );
    }
}
