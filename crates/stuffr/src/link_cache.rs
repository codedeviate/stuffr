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
//! first, to make room for a newer one. At most [`MAX_SPOOLED_LINK_PAYLOADS`]
//! are held on disk at once, so a crafted archive cannot buy one open temp
//! file per entry. The cache never holds more than its policy allows. A link
//! whose target is not kept is the caller's to skip with a warning; nothing
//! here ever hands out a partial or empty stand-in.
//!
//! **Release by count.** cpio announces how many links are to come
//! (`nlink - 1`, less the self-names its reader already dropped), and every
//! `Hardlink` naming a kept payload, copied or skipped, counts one down
//! ([`LinkCache::link_seen`]); at zero the payload is dropped. A count that
//! never reaches zero — an archive holding fewer names than `nlink`, a
//! self-name dropped after the data member, writers that store the data on
//! every link — keeps its payload until it is evicted or the cache is dropped
//! at the end of the archive. tar announces nothing, so its payloads stay
//! until evicted.
//!
//! **An empty target is always available.** A 0-byte regular file is
//! recorded by name ([`LinkCache::keep_empty`]) rather than kept: its copy is
//! exact, costs nothing against the byte budget, is never evicted, and stays
//! until a later entry of the same name supersedes it. This is what GNU cpio
//! writes for an empty file with several names (an all-empty group, which
//! announces nothing), and what a tar link to an empty file needs however
//! long ago it was written.
//!
//! **A link to a link is skipped.** A link written as a copy is not kept in
//! turn, so a later link naming THAT name (rather than the original target)
//! finds nothing kept and is skipped with the pinned reason.

use std::collections::{HashSet, VecDeque};
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

/// The most payloads a [`LinkCache`] holds ON DISK at once, each an open temp
/// file. Past it the oldest on-disk payload is evicted, whatever its link
/// count says: a crafted `nlink` must not buy one file descriptor per entry.
/// Memory-tier payloads are bounded by bytes instead.
pub(crate) const MAX_SPOOLED_LINK_PAYLOADS: usize = 64;

/// One kept payload.
struct Kept {
    name: String,
    bytes: SpillSource,
    /// Links still to come, when the reader announced a count (cpio): the
    /// payload is dropped when it reaches zero. `None` (tar): unknown, kept
    /// until evicted.
    links_left: Option<u32>,
}

/// Payloads kept so a later hard link can be written as a copy.
pub(crate) struct LinkCache {
    policy: CachePolicy,
    /// Oldest first. At most one payload per name: keeping a name replaces
    /// what was kept under it.
    kept: VecDeque<Kept>,
    in_memory: u64,
    on_disk: u64,
    /// How many entries of `kept` are on disk.
    files: usize,
    /// Names of 0-byte files written: always copy-available, at no cost to
    /// the budget, never evicted, and not counted down. One name per empty
    /// file the archive holds — linear in the input, like the names it costs
    /// to read.
    empties: HashSet<String>,
    /// The most `files` has ever been, for the bound's tests.
    #[cfg(test)]
    files_high_water: usize,
}

impl LinkCache {
    pub(crate) fn new(policy: CachePolicy) -> Self {
        Self {
            policy,
            kept: VecDeque::new(),
            in_memory: 0,
            on_disk: 0,
            files: 0,
            empties: HashSet::new(),
            #[cfg(test)]
            files_high_water: 0,
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

    /// Whether this entry's payload should be kept: under `Announced`, when
    /// the reader announced at least one link to come; under `Recent`, any
    /// `File`; `Off`, never.
    pub(crate) fn wants(&self, meta: &EntryMeta, announces_links: Option<u32>) -> bool {
        if meta.kind != EntryKind::File || self.limits().is_none() {
            return false;
        }
        match self.policy {
            CachePolicy::Announced(_) => announces_links.is_some_and(|n| n > 0),
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
        let mut spool = SpillWriter::new(&policy).ok()?;
        if let Some(size) = size {
            spool.reserve(size);
        }
        Some(spool)
    }

    /// Stores `bytes` (already read once, for the write) under `name`, with
    /// the reader's announced count of links to come (`None`: unknown),
    /// evicting the oldest payloads to make room. Silently declines a
    /// payload the policy cannot hold; nothing is kept under `name` then.
    pub(crate) fn keep(&mut self, name: &str, bytes: SpillSource, links_to_come: Option<u32>) {
        self.forget(name);
        let Some(limits) = self.limits() else {
            return;
        };
        if links_to_come == Some(0) {
            return;
        }
        let len = bytes.caps().len.unwrap_or(u64::MAX);
        let disk = bytes.spilled_to_disk();
        if len > limits.total || (disk && limits.disk.is_none()) || (!disk && len > limits.mem) {
            return;
        }
        while self.held() + len > limits.total && self.evict_oldest() {}
        while !disk && self.in_memory + len > limits.mem && self.evict_oldest() {}
        while disk && self.files >= MAX_SPOOLED_LINK_PAYLOADS && self.evict_oldest_on_disk() {}
        if disk {
            self.on_disk += len;
            self.files += 1;
            #[cfg(test)]
            {
                self.files_high_water = self.files_high_water.max(self.files);
            }
        } else {
            self.in_memory += len;
        }
        self.kept.push_back(Kept {
            name: name.to_string(),
            bytes,
            links_left: links_to_come,
        });
    }

    /// Records that a 0-byte regular file was written under `name`. Its copy
    /// is exact without keeping a byte, so it is copy-available whatever the
    /// byte budget, until a later entry of the same name supersedes it.
    /// Nothing under [`CachePolicy::Off`], where no link is ever copied.
    pub(crate) fn keep_empty(&mut self, name: &str) {
        self.forget(name);
        if self.policy != CachePolicy::Off {
            self.empties.insert(name.to_string());
        }
    }

    /// Whether `target`'s bytes are kept.
    pub(crate) fn contains(&self, target: &str) -> bool {
        self.empties.contains(target) || self.kept.iter().any(|k| k.name == target)
    }

    /// A fresh reader over `target`'s bytes, with their length, or `None`
    /// if not kept.
    pub(crate) fn copy_of(
        &mut self,
        target: &str,
    ) -> stuffr_core::Result<Option<(u64, Box<dyn Read + '_>)>> {
        if self.empties.contains(target) {
            return Ok(Some((0, Box::new(std::io::empty()))));
        }
        let Some(kept) = self.kept.iter_mut().find(|k| k.name == target) else {
            return Ok(None);
        };
        let len = kept.bytes.caps().len.unwrap_or(0);
        if let Some(seek) = kept.bytes.as_seek() {
            seek.seek(SeekFrom::Start(0))?;
        }
        Ok(Some((len, Box::new(&mut kept.bytes))))
    }

    /// A hard link naming `target` has passed — copied or skipped. A payload
    /// with an announced count drops when its last link has; one without a
    /// count (tar) is unaffected.
    pub(crate) fn link_seen(&mut self, target: &str) {
        let Some(i) = self.kept.iter().position(|k| k.name == target) else {
            return;
        };
        let Some(left) = self.kept[i].links_left.as_mut() else {
            return;
        };
        *left = left.saturating_sub(1);
        if *left == 0
            && let Some(kept) = self.kept.remove(i)
        {
            self.release(&kept.bytes);
        }
    }

    /// Drops whatever is kept under `name`.
    pub(crate) fn forget(&mut self, name: &str) {
        self.empties.remove(name);
        while let Some(i) = self.kept.iter().position(|k| k.name == name) {
            if let Some(kept) = self.kept.remove(i) {
                self.release(&kept.bytes);
            }
        }
    }

    /// Drops the oldest payload, answering whether there was one.
    fn evict_oldest(&mut self) -> bool {
        match self.kept.pop_front() {
            Some(kept) => {
                self.release(&kept.bytes);
                true
            }
            None => false,
        }
    }

    /// Drops the oldest payload held on disk, answering whether there was
    /// one.
    fn evict_oldest_on_disk(&mut self) -> bool {
        let Some(i) = self.kept.iter().position(|k| k.bytes.spilled_to_disk()) else {
            return false;
        };
        if let Some(kept) = self.kept.remove(i) {
            self.release(&kept.bytes);
        }
        true
    }

    /// Un-counts a payload leaving the cache. Dropping its `SpillSource`
    /// closes (and so deletes) its temp file.
    fn release(&mut self, bytes: &SpillSource) {
        let len = bytes.caps().len.unwrap_or(0);
        if bytes.spilled_to_disk() {
            self.on_disk -= len;
            self.files -= 1;
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
        put_counted(cache, name, bytes, None);
    }

    /// [`put`], with an announced count of links to come.
    fn put_counted(cache: &mut LinkCache, name: &str, bytes: &[u8], links: Option<u32>) {
        let mut spool = cache.spool(name, Some(bytes.len() as u64));
        let mut src = bytes;
        let mut tee = Tee::new(&mut src, &mut spool);
        let mut sink = Vec::new();
        tee.read_to_end(&mut sink).unwrap();
        assert_eq!(sink, bytes, "the tee never alters what the writer reads");
        if let Some(spool) = spool {
            cache.keep(name, spool.finish().unwrap(), links);
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
        assert!(cache.wants(&file("a"), None));
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
        assert!(!cache.wants(&file("a"), Some(1)));
        assert!(cache.spool("a", Some(1)).is_none());
        let src = SpillSource::materialize_from(&mut &b"x"[..], &SpillPolicy::default()).unwrap();
        cache.keep("a", src, None);
        assert!(read_back(&mut cache, "a").is_none());
        // Off by spill policy too, and for every source but cpio and tar.
        let off = LinkCache::new(CachePolicy::Announced(SpillPolicy::Off));
        assert!(!off.wants(&file("a"), Some(1)));
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
        assert!(!cache.wants(&file("a"), None));
        assert!(!cache.wants(&file("a"), Some(0)));
        assert!(cache.wants(&file("a"), Some(1)));
        let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        put_counted(&mut cache, "a", &payload, Some(1));
        assert_eq!(cache.on_disk, 2048, "past the memory tier, on disk");
        assert_eq!(cache.in_memory, 0);
        assert_eq!(read_back(&mut cache, "a").unwrap(), payload);
    }

    /// An announced payload is dropped once its last link has passed —
    /// copied or skipped alike — freeing its share of the policy; a payload
    /// with no count (tar) is not.
    #[test]
    fn an_announced_payload_is_released_by_its_link_count() {
        let mut cache = LinkCache::new(CachePolicy::Announced(SpillPolicy::Memory { cap: 100 }));
        put_counted(&mut cache, "a", b"shared", Some(2));
        cache.link_seen("a");
        assert_eq!(read_back(&mut cache, "a").unwrap(), b"shared");
        cache.link_seen("a");
        assert!(!cache.contains("a"), "dropped after its second link");
        assert_eq!(cache.held(), 0);
        // A link naming nothing kept is a no-op.
        cache.link_seen("a");
        let mut tar = LinkCache::new(CachePolicy::Recent { cap: 100 });
        put(&mut tar, "t", b"x");
        tar.link_seen("t");
        tar.link_seen("t");
        assert!(tar.contains("t"), "tar announces nothing to count down");
    }

    /// Whatever counts a crafted archive announces, no more than
    /// `MAX_SPOOLED_LINK_PAYLOADS` temp files are open at once: the oldest
    /// on-disk payload goes first. Memory-tier payloads are not displaced.
    #[test]
    fn spooled_payloads_are_bounded_whatever_the_counts_say() {
        let mut cache = LinkCache::new(CachePolicy::Announced(SpillPolicy::Temp {
            dir: None,
            mem_cap: 4,
            max: 1 << 20,
        }));
        put_counted(&mut cache, "m", b"mem", Some(9));
        for i in 0..(MAX_SPOOLED_LINK_PAYLOADS + 20) {
            put_counted(&mut cache, &format!("d{i}"), b"on disk!", Some(9));
        }
        assert_eq!(cache.files, MAX_SPOOLED_LINK_PAYLOADS);
        assert_eq!(cache.files_high_water, MAX_SPOOLED_LINK_PAYLOADS);
        assert!(cache.contains("m"), "the memory tier keeps its own bound");
        assert!(!cache.contains("d0"), "the oldest file went first");
        assert!(cache.contains(&format!("d{}", MAX_SPOOLED_LINK_PAYLOADS + 19)));
    }

    /// An empty file is copy-available without a byte of budget, however
    /// much was evicted since, until a same-name entry supersedes it; under
    /// `Off`, nothing is recorded.
    #[test]
    fn an_empty_file_is_always_copy_available() {
        let mut cache = LinkCache::new(CachePolicy::Recent { cap: 4 });
        cache.keep_empty("e");
        for i in 0..10 {
            put(&mut cache, &format!("f{i}"), b"abcd");
        }
        assert!(cache.contains("e"));
        assert_eq!(read_back(&mut cache, "e").unwrap(), b"");
        cache.link_seen("e");
        assert!(cache.contains("e"), "not counted down");
        put(&mut cache, "e", b"new!");
        assert_eq!(read_back(&mut cache, "e").unwrap(), b"new!");
        cache.forget("e");
        assert!(!cache.contains("e"));
        let mut off = LinkCache::new(CachePolicy::Off);
        off.keep_empty("e");
        assert!(!off.contains("e"));
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
