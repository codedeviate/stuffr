//! The pax records the `tar` crate (0.4.46) hands over but does not
//! interpret: GNU's pax sparse maps (`GNU.sparse.*`) and the `mtime` record.
//! `tar.rs`'s reader applies both (bug hunt 2026-11-15, findings 4 and 25).
//!
//! # pax sparse files
//!
//! A sparse file in a pax archive is an ordinary regular-file entry whose
//! payload holds only the file's data regions, back to back, with a map of
//! where each belongs; the crate reads that entry as a plain file, so it came
//! back under its placeholder name (`GNUSparseFile.0/big`) with the stored
//! regions (and, for 1.0, the map's text) as its content — and "exact
//! fidelity". GNU tar's three layouts are all read here:
//!
//! | version | written by | real name | real size | map |
//! |---|---|---|---|---|
//! | 1.0 | macOS `/usr/bin/tar` (bsdtar) for any file with a hole; `gtar --sparse --format=pax` | `GNU.sparse.name` | `GNU.sparse.realsize` | decimal lines at the head of the payload, padded to 512 bytes |
//! | 0.1 | `gtar --sparse-version=0.1` | `GNU.sparse.name` | `GNU.sparse.size` | `GNU.sparse.map=off,len,off,len,...` |
//! | 0.0 | `gtar --sparse-version=0.0` | the header's own name | `GNU.sparse.size` | repeated `GNU.sparse.offset` / `GNU.sparse.numbytes` records |
//!
//! The entry is delivered under its real name and real size, holes read as
//! zeros, exactly what `/usr/bin/tar -xf` writes (byte for byte; a hole is
//! written as zeros, not punched). A larger version (`GNU.sparse.major` other
//! than 1, or `minor` other than 0) is refused as unsupported (exit 3): its
//! name and contents cannot be told, and the placeholder must never be handed
//! back as though it were the file.
//!
//! A map that contradicts itself is `Corrupt` (exit 5): regions out of order
//! or overlapping, a region past the real size, a number that is not a
//! decimal `u64`, a 1.0 map that runs out of payload, region lengths that do
//! not add up to the stored data. More than [`MAX_SPARSE_REGIONS`] regions is
//! `ResourceLimit` (exit 6), refused before the region list grows past it —
//! the figure `tar.rs`'s old-GNU (`S`) path already holds a map to
//! (`MAX_GNU_SPARSE_EXT_BLOCKS` × 21 regions per block). Expanding holes
//! costs no memory: the zeros are produced, never buffered, and every byte
//! delivered is charged to the read verb's `--max-ratio` budget like any
//! other entry's, so a 1 TiB real size over 1 KiB of data is refused there
//! (exit 6) rather than written.
//!
//! # pax `mtime`
//!
//! A writer puts the real time in the pax `mtime` record — signed decimal
//! seconds with an optional fraction — whenever the header's 11-octal-digit
//! field cannot hold it (before 1970, or from 2242), leaving the field 0 or
//! clamped. The record wins over the field, as in every tar tool. A GNU
//! base-256 NEGATIVE field (GNU tar's own spelling of a pre-1970 time) is
//! read too. A time that is present but cannot be read or represented is
//! [`stuffr_core::Fidelity::MetadataIncomplete`] for `mtime`, never a silent
//! 1970 or a silent "now".

use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stuffr_core::{Error, Result};

use crate::tar::{BLOCK, MAX_GNU_SPARSE_EXT_BLOCKS};

/// The most data regions one pax sparse map may declare: the number the
/// old-GNU (`S`) path's extension-chain ceiling admits, 32,768 blocks of 21
/// regions each — 688,128, far past any real file's map. 16 bytes a region
/// held, so at most 11 MiB. [`Error::ResourceLimit`] (exit 6) past it.
pub const MAX_SPARSE_REGIONS: u64 = MAX_GNU_SPARSE_EXT_BLOCKS * 21;

/// What a header or pax record says about an entry's modification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeField {
    /// A time, read and representable.
    Known(SystemTime),
    /// A time is recorded, but it does not parse or [`SystemTime`] cannot
    /// hold it: the entry's mtime is unknown, and that is a loss to report.
    Unusable,
}

impl TimeField {
    pub(crate) fn time(self) -> Option<SystemTime> {
        match self {
            TimeField::Known(t) => Some(t),
            TimeField::Unusable => None,
        }
    }
}

/// A pax `mtime` (or `atime`/`ctime`) value: `-?DIGITS(.DIGITS)?`, seconds
/// from the epoch. Fraction digits past nine (nanoseconds) are ignored.
pub(crate) fn pax_time(value: &[u8]) -> TimeField {
    let (negative, rest) = match value.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, value),
    };
    let (whole, fraction) = match rest.iter().position(|&b| b == b'.') {
        Some(dot) => (&rest[..dot], Some(&rest[dot + 1..])),
        None => (rest, None),
    };
    let Some(secs) = decimal_u64(whole) else {
        return TimeField::Unusable;
    };
    let mut nanos = 0u32;
    if let Some(fraction) = fraction {
        if !fraction.iter().all(u8::is_ascii_digit) {
            return TimeField::Unusable;
        }
        for i in 0..9 {
            nanos = nanos * 10 + fraction.get(i).map_or(0, |d| u32::from(d - b'0'));
        }
    }
    let span = Duration::new(secs, nanos);
    let time = if negative {
        UNIX_EPOCH.checked_sub(span)
    } else {
        UNIX_EPOCH.checked_add(span)
    };
    time.map_or(TimeField::Unusable, TimeField::Known)
}

/// The header's own `mtime` field: octal, GNU base-256 positive (as the
/// crate reads it), or GNU base-256 NEGATIVE (a leading `0xff`, two's
/// complement), which the crate reads as a huge unsigned number.
///
/// An empty field (every byte NUL or a blank) is no time at all and reads
/// as 0, as bsdtar reads it, with nothing to report.
pub(crate) fn header_time(header: &tar::Header) -> TimeField {
    let field = &header.as_old().mtime;
    if field.iter().all(|&b| b == 0 || b == b' ') {
        return TimeField::Known(UNIX_EPOCH);
    }
    if field[0] == 0xff {
        // Twelve bytes of two's complement; a value that fits an `i64` has
        // its top four bytes all set and the fifth's sign bit set.
        let (high, low) = field.split_at(4);
        if high.iter().all(|&b| b == 0xff) && low[0] & 0x80 != 0 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(low);
            let secs = i64::from_be_bytes(bytes);
            return UNIX_EPOCH
                .checked_sub(Duration::from_secs(secs.unsigned_abs()))
                .map_or(TimeField::Unusable, TimeField::Known);
        }
        return TimeField::Unusable;
    }
    match header.mtime() {
        Ok(secs) => UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .map_or(TimeField::Unusable, TimeField::Known),
        Err(_) => TimeField::Unusable,
    }
}

/// A decimal `u64`: one or more ASCII digits and nothing else.
fn decimal_u64(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

/// The pax records of one entry that the crate does not apply: `mtime`, and
/// everything under `GNU.sparse.`, gathered in one pass over the records.
///
/// 0.0's repeated `offset`/`numbytes` pairs are parsed into regions as they
/// pass rather than kept as text, under [`MAX_SPARSE_REGIONS`]; the first
/// fault is kept and raised only if the entry turns out to be sparse.
#[derive(Default)]
pub(crate) struct PaxRecords {
    pub(crate) mtime: Option<Vec<u8>>,
    sparse: SparseRecords,
}

#[derive(Default)]
struct SparseRecords {
    /// Any `GNU.sparse.*` record at all.
    seen: bool,
    major: Option<Vec<u8>>,
    minor: Option<Vec<u8>>,
    name: Option<Vec<u8>>,
    realsize: Option<Vec<u8>>,
    size: Option<Vec<u8>>,
    numblocks: Option<Vec<u8>>,
    map: Option<Vec<u8>>,
    /// 0.0's pairs, in record order.
    pairs: Vec<(u64, u64)>,
    pending_offset: Option<u64>,
    /// 0.0 records were met.
    old_pairs: bool,
    fault: Option<MapFault>,
}

/// A fault found while gathering 0.0's pairs, raised later as an error.
enum MapFault {
    Corrupt(String),
    TooMany,
}

impl PaxRecords {
    /// Gathers what this module interprets. Records that do not parse are
    /// skipped, as the crate's own `path`/`linkpath` lookups skip them.
    pub(crate) fn collect(exts: tar::PaxExtensions<'_>) -> Self {
        let mut out = PaxRecords::default();
        for record in exts.filter_map(io::Result::ok) {
            let key = record.key_bytes();
            let value = record.value_bytes();
            if key == b"mtime" {
                out.mtime = Some(value.to_vec());
                continue;
            }
            let Some(field) = key.strip_prefix(b"GNU.sparse.") else {
                continue;
            };
            let s = &mut out.sparse;
            s.seen = true;
            match field {
                b"major" => s.major = Some(value.to_vec()),
                b"minor" => s.minor = Some(value.to_vec()),
                b"name" => s.name = Some(value.to_vec()),
                b"realsize" => s.realsize = Some(value.to_vec()),
                b"size" => s.size = Some(value.to_vec()),
                b"numblocks" => s.numblocks = Some(value.to_vec()),
                b"map" => s.map = Some(value.to_vec()),
                b"offset" => s.offset(value),
                b"numbytes" => s.numbytes(value),
                _ => {}
            }
        }
        out
    }

    /// The entry's sparse plan, `None` when it carries no `GNU.sparse.*`
    /// record. `name` names the entry in a refusal.
    pub(crate) fn sparse_plan(&mut self, name: &str) -> Result<Option<SparsePlan>> {
        let s = std::mem::take(&mut self.sparse);
        if !s.seen {
            return Ok(None);
        }
        let corrupt = |why: &str| Error::Corrupt(format!("tar pax sparse entry `{name}`: {why}"));
        let number = |value: &Option<Vec<u8>>, what: &str| -> Result<u64> {
            let Some(value) = value else {
                return Err(corrupt(&format!("no `GNU.sparse.{what}` record")));
            };
            decimal_u64(value).ok_or_else(|| {
                corrupt(&format!(
                    "`GNU.sparse.{what}` is `{}`, not a decimal number",
                    String::from_utf8_lossy(value)
                ))
            })
        };
        if s.major.is_some() || s.minor.is_some() {
            let (major, minor) = (s.major.as_deref(), s.minor.as_deref());
            if major != Some(b"1") || minor != Some(b"0") {
                return Err(Error::Unsupported(format!(
                    "tar entry `{name}` is a pax sparse file of format {}.{}, which this \
                     build cannot expand (it reads 0.0, 0.1 and 1.0)",
                    String::from_utf8_lossy(major.unwrap_or(b"?")),
                    String::from_utf8_lossy(minor.unwrap_or(b"?")),
                )));
            }
            let realsize = number(&s.realsize, "realsize")?;
            let Some(real_name) = s.name else {
                return Err(corrupt("format 1.0 with no `GNU.sparse.name` record"));
            };
            return Ok(Some(SparsePlan {
                name: Some(real_name),
                realsize,
                regions: Regions::InPayload,
            }));
        }
        let realsize = number(&s.size, "size")?;
        let regions = if let Some(map) = &s.map {
            if s.old_pairs {
                return Err(corrupt("both a `GNU.sparse.map` and 0.0 offset records"));
            }
            if s.name.is_none() {
                return Err(corrupt("format 0.1 with no `GNU.sparse.name` record"));
            }
            parse_comma_map(map).map_err(|f| fault_error(f, name))?
        } else if s.old_pairs || s.numblocks.is_some() {
            if let Some(fault) = s.fault {
                return Err(fault_error(fault, name));
            }
            if s.pending_offset.is_some() {
                return Err(corrupt("a `GNU.sparse.offset` with no `numbytes` after it"));
            }
            s.pairs
        } else {
            return Err(Error::Unsupported(format!(
                "tar entry `{name}` carries `GNU.sparse` records of no layout this build \
                 knows (0.0, 0.1 or 1.0), so its real name and contents cannot be told"
            )));
        };
        if s.numblocks.is_some() {
            let declared = number(&s.numblocks, "numblocks")?;
            if declared != regions.len() as u64 {
                return Err(corrupt(&format!(
                    "`GNU.sparse.numblocks` is {declared} but the map lists {} regions",
                    regions.len()
                )));
            }
        }
        Ok(Some(SparsePlan {
            name: s.name,
            realsize,
            regions: Regions::Known(regions),
        }))
    }
}

impl SparseRecords {
    fn offset(&mut self, value: &[u8]) {
        self.old_pairs = true;
        if self.fault.is_some() {
            return;
        }
        if self.pending_offset.is_some() {
            self.fault = Some(MapFault::Corrupt(
                "two `GNU.sparse.offset` records with no `numbytes` between them".into(),
            ));
            return;
        }
        match decimal_u64(value) {
            Some(v) => self.pending_offset = Some(v),
            None => self.fault = Some(not_a_number("offset", value)),
        }
    }

    fn numbytes(&mut self, value: &[u8]) {
        self.old_pairs = true;
        if self.fault.is_some() {
            return;
        }
        let Some(offset) = self.pending_offset.take() else {
            self.fault = Some(MapFault::Corrupt(
                "a `GNU.sparse.numbytes` with no `offset` before it".into(),
            ));
            return;
        };
        let Some(len) = decimal_u64(value) else {
            self.fault = Some(not_a_number("numbytes", value));
            return;
        };
        if self.pairs.len() as u64 >= MAX_SPARSE_REGIONS {
            self.fault = Some(MapFault::TooMany);
            return;
        }
        self.pairs.push((offset, len));
    }
}

fn not_a_number(what: &str, value: &[u8]) -> MapFault {
    MapFault::Corrupt(format!(
        "`GNU.sparse.{what}` is `{}`, not a decimal number",
        String::from_utf8_lossy(value)
    ))
}

fn fault_error(fault: MapFault, name: &str) -> Error {
    match fault {
        MapFault::Corrupt(why) => Error::Corrupt(format!("tar pax sparse entry `{name}`: {why}")),
        MapFault::TooMany => too_many_regions(name),
    }
}

fn too_many_regions(name: &str) -> Error {
    Error::ResourceLimit(format!(
        "tar pax sparse entry `{name}` maps more than {MAX_SPARSE_REGIONS} data regions, \
         past the ceiling this container holds a sparse map to; no real sparse file's \
         map is this large"
    ))
}

/// 0.1's `off,len,off,len,...`.
fn parse_comma_map(map: &[u8]) -> std::result::Result<Vec<(u64, u64)>, MapFault> {
    if map.is_empty() {
        return Ok(Vec::new());
    }
    let mut regions = Vec::new();
    let mut fields = map.split(|&b| b == b',');
    while let Some(off) = fields.next() {
        let Some(len) = fields.next() else {
            return Err(MapFault::Corrupt(
                "`GNU.sparse.map` has an offset with no length".into(),
            ));
        };
        let (Some(off), Some(len)) = (decimal_u64(off), decimal_u64(len)) else {
            return Err(MapFault::Corrupt(format!(
                "`GNU.sparse.map` holds `{}`, not decimal numbers",
                String::from_utf8_lossy(map.get(..64).unwrap_or(map))
            )));
        };
        if regions.len() as u64 >= MAX_SPARSE_REGIONS {
            return Err(MapFault::TooMany);
        }
        regions.push((off, len));
    }
    Ok(regions)
}

/// How a sparse entry is to be read back.
pub(crate) struct SparsePlan {
    /// The real name, when the records carry one (`None` for 0.0, whose
    /// header names the file itself).
    pub(crate) name: Option<Vec<u8>>,
    pub(crate) realsize: u64,
    regions: Regions,
}

enum Regions {
    /// 1.0: the map heads the payload.
    InPayload,
    Known(Vec<(u64, u64)>),
}

impl SparsePlan {
    /// Reads a 1.0 map off the front of `payload` (whose length is
    /// `payload_len`), checks the map against the real size and the stored
    /// data, and returns the expanding reader. `name` is the real name, for
    /// refusals.
    pub(crate) fn reader<R: Read>(
        self,
        mut payload: R,
        payload_len: u64,
        name: &str,
    ) -> Result<SparseReader<R>> {
        let (regions, data_len) = match self.regions {
            Regions::Known(regions) => (regions, payload_len),
            Regions::InPayload => {
                let (regions, used) = read_v1_map(&mut payload, payload_len, name)?;
                (regions, payload_len - used)
            }
        };
        check_regions(&regions, self.realsize, data_len, name)?;
        Ok(SparseReader {
            inner: payload,
            regions,
            next: 0,
            pos: 0,
            realsize: self.realsize,
        })
    }
}

/// Reads 1.0's map: decimal lines (a count, then that many offset/length
/// pairs) padded to a whole block. Returns the regions and how many payload
/// bytes the map took.
fn read_v1_map<R: Read>(
    payload: &mut R,
    payload_len: u64,
    name: &str,
) -> Result<(Vec<(u64, u64)>, u64)> {
    let corrupt = |why: String| Error::Corrupt(format!("tar pax sparse entry `{name}`: {why}"));
    let mut block = [0u8; BLOCK];
    let mut used = 0u64;
    let mut at = BLOCK;
    let mut digits: Vec<u8> = Vec::with_capacity(20);
    let mut count: Option<u64> = None;
    let mut first: Option<u64> = None;
    let mut regions: Vec<(u64, u64)> = Vec::new();
    loop {
        if count.is_some_and(|c| regions.len() as u64 == c) {
            return Ok((regions, used));
        }
        if at == BLOCK {
            if used + BLOCK as u64 > payload_len {
                return Err(corrupt(format!(
                    "its sparse map runs past the {payload_len}-byte payload that holds it"
                )));
            }
            payload
                .read_exact(&mut block)
                .map_err(Error::from_decode_io)?;
            used += BLOCK as u64;
            at = 0;
        }
        let b = block[at];
        at += 1;
        if b != b'\n' {
            if !b.is_ascii_digit() || digits.len() == 20 {
                return Err(corrupt(format!(
                    "its sparse map holds byte {b:#04x} where a decimal number belongs"
                )));
            }
            digits.push(b);
            continue;
        }
        let Some(n) = decimal_u64(&digits) else {
            return Err(corrupt(
                "its sparse map holds an empty or oversized decimal number".into(),
            ));
        };
        digits.clear();
        match (count, first) {
            (None, _) => {
                // Each pair takes at least four bytes ("0\n0\n"), so a count
                // the payload cannot hold is the file contradicting itself;
                // one it can hold but past the ceiling is a resource refusal.
                if n.saturating_mul(4) > payload_len {
                    return Err(corrupt(format!(
                        "its sparse map declares {n} regions, more than its \
                         {payload_len}-byte payload can hold"
                    )));
                }
                if n > MAX_SPARSE_REGIONS {
                    return Err(too_many_regions(name));
                }
                count = Some(n);
            }
            (Some(_), None) => first = Some(n),
            (Some(_), Some(offset)) => {
                regions.push((offset, n));
                first = None;
            }
        }
    }
}

/// Regions in order, not overlapping, inside the real size, and adding up
/// to exactly the stored data.
fn check_regions(regions: &[(u64, u64)], realsize: u64, data_len: u64, name: &str) -> Result<()> {
    let corrupt = |why: String| Error::Corrupt(format!("tar pax sparse entry `{name}`: {why}"));
    let mut end = 0u64;
    let mut stored = 0u64;
    for &(offset, len) in regions {
        if offset < end {
            return Err(corrupt(format!(
                "its sparse map places a region at offset {offset}, before the end of the \
                 previous one ({end}); regions must be in order and must not overlap"
            )));
        }
        end = match offset.checked_add(len) {
            Some(e) if e <= realsize => e,
            _ => {
                return Err(corrupt(format!(
                    "its sparse map places {len} bytes at offset {offset}, past the \
                     file's real size of {realsize} bytes"
                )));
            }
        };
        stored += len;
    }
    if stored != data_len {
        return Err(corrupt(format!(
            "its sparse map accounts for {stored} stored bytes but the entry holds \
             {data_len}"
        )));
    }
    Ok(())
}

/// A sparse entry's logical contents: each region's stored bytes at its
/// offset, zeros everywhere else, `realsize` bytes in all. Nothing is
/// buffered; a hole costs no memory however large it is.
pub(crate) struct SparseReader<R> {
    inner: R,
    regions: Vec<(u64, u64)>,
    /// The region not yet finished.
    next: usize,
    /// Logical bytes delivered so far.
    pos: u64,
    realsize: u64,
}

impl<R: Read> Read for SparseReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos == self.realsize {
                return Ok(0);
            }
            let Some(&(offset, len)) = self.regions.get(self.next) else {
                return Ok(self.zeros(buf, self.realsize));
            };
            if self.pos < offset {
                return Ok(self.zeros(buf, offset));
            }
            let end = offset + len;
            if self.pos >= end {
                self.next += 1;
                continue;
            }
            let want = usize::try_from(end - self.pos).map_or(buf.len(), |n| n.min(buf.len()));
            let n = self.inner.read(&mut buf[..want])?;
            if n == 0 {
                // The payload reader below raises truncation itself; this
                // only stops a reader that does not from looping forever.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tar pax sparse entry: stored data ended before its map did",
                ));
            }
            self.pos += n as u64;
            return Ok(n);
        }
    }
}

impl<R> SparseReader<R> {
    /// Fills `buf` with zeros up to logical offset `until`.
    fn zeros(&mut self, buf: &mut [u8], until: u64) -> usize {
        let n = usize::try_from(until - self.pos).map_or(buf.len(), |n| n.min(buf.len()));
        buf[..n].fill(0);
        self.pos += n as u64;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tar::{TAR, Tar};
    use stuffr_core::{
        ArchiveRead, Container, Fidelity, OpenOpts, ReaderSource, Source, StreamPolicy,
    };

    /// A pax `x` header carrying `records`, then a regular entry named
    /// `header_name` holding `payload`.
    fn pax_entry(records: &[(&str, &[u8])], header_name: &str, payload: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        if !records.is_empty() {
            builder
                .append_pax_extensions(records.iter().map(|(k, v)| (*k, *v)))
                .unwrap();
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1_700_000_000);
        builder
            .append_data(&mut header, header_name, payload)
            .unwrap();
        builder.into_inner().unwrap()
    }

    /// A 1.0 payload: the map's decimal lines padded to a block, then each
    /// region's data back to back.
    fn v1_payload(regions: &[(u64, &[u8])]) -> Vec<u8> {
        let mut map = format!("{}\n", regions.len());
        for (offset, data) in regions {
            map += &format!("{offset}\n{}\n", data.len());
        }
        let mut payload = map.into_bytes();
        payload.resize(payload.len().div_ceil(BLOCK) * BLOCK, 0);
        for (_, data) in regions {
            payload.extend_from_slice(data);
        }
        payload
    }

    fn v1(name: &str, realsize: u64, payload: &[u8]) -> Vec<u8> {
        let realsize = realsize.to_string();
        pax_entry(
            &[
                ("GNU.sparse.major", b"1"),
                ("GNU.sparse.minor", b"0"),
                ("GNU.sparse.name", name.as_bytes()),
                ("GNU.sparse.realsize", realsize.as_bytes()),
            ],
            &format!("GNUSparseFile.0/{name}"),
            payload,
        )
    }

    /// What `regions` expands to in a file of `realsize` bytes.
    fn expanded(regions: &[(u64, &[u8])], realsize: u64) -> Vec<u8> {
        let mut out = vec![0u8; realsize as usize];
        for (offset, data) in regions {
            out[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
        }
        out
    }

    fn open_pipe(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())));
        let resolved =
            stuffr_core::resolve(src, TAR, Tar.caps(), &StreamPolicy::default()).expect("resolve");
        Tar.open(resolved, &OpenOpts::default()).expect("open")
    }

    fn open_file(bytes: &[u8]) -> Box<dyn ArchiveRead> {
        let path = std::env::temp_dir().join(format!(
            "stuffr-tarpax-{}-{:p}.tar",
            std::process::id(),
            bytes
        ));
        std::fs::write(&path, bytes).unwrap();
        let src: Box<dyn Source> = Box::new(stuffr_core::FileSource::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let resolved =
            stuffr_core::resolve(src, TAR, Tar.caps(), &StreamPolicy::default()).expect("resolve");
        Tar.open(resolved, &OpenOpts::default()).expect("open")
    }

    type ReadBack = (String, Option<u64>, Vec<u8>);

    /// `(name, declared size, contents)` of every entry, or the first error
    /// — through both a pipe and a file, which must agree.
    fn read_all(bytes: &[u8]) -> Result<Vec<ReadBack>> {
        let walk = |mut ar: Box<dyn ArchiveRead>| -> Result<Vec<_>> {
            let mut out = Vec::new();
            while let Some(mut entry) = ar.next_entry()? {
                let (name, size) = (entry.meta().name.clone(), entry.meta().size);
                let mut data = Vec::new();
                entry
                    .reader()
                    .read_to_end(&mut data)
                    .map_err(Error::from_decode_io)?;
                out.push((name, size, data));
            }
            Ok(out)
        };
        let piped = walk(open_pipe(bytes));
        let filed = walk(open_file(bytes));
        assert_eq!(
            format!("{piped:?}"),
            format!("{filed:?}"),
            "pipe and file disagree"
        );
        piped
    }

    fn error_of(bytes: &[u8]) -> Error {
        read_all(bytes).expect_err("must be refused")
    }

    const REGIONS: &[(u64, &[u8])] = &[(0, b"hello"), (70_000, b"world"), (99_990, b"tail")];

    /// Finding 4: a 1.0 entry (what macOS tar writes for any file with a
    /// hole) reads under its real name, at its real size, holes as zeros —
    /// never the placeholder name with the map as content.
    #[test]
    fn a_pax_1_0_sparse_entry_reads_as_the_file_it_stores() {
        let archive = v1("big", 100_000, &v1_payload(REGIONS));
        let entries = read_all(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        let (name, size, data) = &entries[0];
        assert_eq!(name, "big");
        assert_eq!(*size, Some(100_000));
        assert!(data == &expanded(REGIONS, 100_000), "contents differ");
    }

    /// A trailing zero-length region at the real size (bsdtar writes one) and
    /// a hole at the end are both fine.
    #[test]
    fn a_trailing_empty_region_and_a_trailing_hole_read() {
        let regions: &[(u64, &[u8])] = &[(4096, b"x"), (10_000, b"")];
        let archive = v1("f", 10_000, &v1_payload(regions));
        let (name, size, data) = read_all(&archive).unwrap().remove(0);
        assert_eq!((name.as_str(), size), ("f", Some(10_000)));
        assert!(data == expanded(regions, 10_000));
    }

    fn v0_1(map: &str, realsize: u64, data: &[u8]) -> Vec<u8> {
        let realsize = realsize.to_string();
        pax_entry(
            &[
                ("GNU.sparse.size", realsize.as_bytes()),
                ("GNU.sparse.name", b"big"),
                ("GNU.sparse.map", map.as_bytes()),
            ],
            "./GNUSparseFile.1/big",
            data,
        )
    }

    #[test]
    fn a_pax_0_1_sparse_entry_reads_as_the_file_it_stores() {
        let archive = v0_1("0,5,70000,5,99990,4", 100_000, b"helloworldtail");
        let (name, size, data) = read_all(&archive).unwrap().remove(0);
        assert_eq!((name.as_str(), size), ("big", Some(100_000)));
        assert!(data == expanded(REGIONS, 100_000));
    }

    #[test]
    fn a_pax_0_0_sparse_entry_reads_as_the_file_it_stores() {
        let archive = pax_entry(
            &[
                ("GNU.sparse.size", b"100000"),
                ("GNU.sparse.numblocks", b"3"),
                ("GNU.sparse.offset", b"0"),
                ("GNU.sparse.numbytes", b"5"),
                ("GNU.sparse.offset", b"70000"),
                ("GNU.sparse.numbytes", b"5"),
                ("GNU.sparse.offset", b"99990"),
                ("GNU.sparse.numbytes", b"4"),
            ],
            "big",
            b"helloworldtail",
        );
        let (name, size, data) = read_all(&archive).unwrap().remove(0);
        assert_eq!((name.as_str(), size), ("big", Some(100_000)));
        assert!(data == expanded(REGIONS, 100_000));
    }

    fn assert_corrupt(bytes: &[u8], says: &str) {
        match error_of(bytes) {
            Error::Corrupt(m) => assert!(m.contains(says), "{m}"),
            other => panic!("expected Corrupt containing {says:?}, got {other:?}"),
        }
    }

    /// Every hostile map is exit 5 (or 6 past the region ceiling), on a pipe
    /// and a file alike — never a panic, a hang, or the raw payload.
    #[test]
    fn a_map_that_contradicts_itself_is_corrupt() {
        // Overlapping, out of order, past the real size.
        let overlap = "2\n0\n10\n5\n10\n";
        let backwards = "2\n50\n1\n0\n1\n";
        let past_end = "1\n99\n5\n";
        for (map, data_len, says) in [
            (overlap, 20, "overlap"),
            (backwards, 2, "overlap"),
            (past_end, 5, "past the file's real size"),
        ] {
            let mut payload = map.as_bytes().to_vec();
            payload.resize(BLOCK, 0);
            payload.extend(std::iter::repeat_n(b'd', data_len));
            assert_corrupt(&v1("f", 100, &payload), says);
        }
        // Not a number.
        let mut payload = b"1\n0\nx5\n".to_vec();
        payload.resize(BLOCK, 0);
        assert_corrupt(&v1("f", 100, &payload), "decimal number");
        // A number that overflows a u64.
        let mut payload = b"1\n0\n99999999999999999999\n".to_vec();
        payload.resize(BLOCK, 0);
        assert_corrupt(&v1("f", 100, &payload), "decimal number");
        // A count the payload cannot hold.
        let mut payload = b"99999999999\n".to_vec();
        payload.resize(BLOCK, 0);
        assert_corrupt(&v1("f", 100, &payload), "can hold");
        // A map that never ends: numbers to the end of the payload.
        let mut payload = b"200\n".to_vec();
        payload.extend(b"1000000\n".repeat(127));
        payload.extend(b"999\n");
        assert_corrupt(&v1("f", 100, &payload), "runs past");
        // More stored data than the map accounts for.
        let mut payload = v1_payload(&[(0, b"abc")]);
        payload.extend_from_slice(b"extra");
        assert_corrupt(&v1("f", 100, &payload), "accounts for");
        // A real size that is not a number.
        let archive = pax_entry(
            &[
                ("GNU.sparse.major", b"1"),
                ("GNU.sparse.minor", b"0"),
                ("GNU.sparse.name", b"f"),
                ("GNU.sparse.realsize", b"-1"),
            ],
            "GNUSparseFile.0/f",
            &v1_payload(&[]),
        );
        assert_corrupt(&archive, "realsize");
        // 0.1: an odd map, and a numblocks that disagrees.
        assert_corrupt(&v0_1("0,5,9", 100, b"hello"), "no length");
        let archive = pax_entry(
            &[
                ("GNU.sparse.size", b"100"),
                ("GNU.sparse.numblocks", b"2"),
                ("GNU.sparse.offset", b"0"),
                ("GNU.sparse.numbytes", b"5"),
            ],
            "f",
            b"hello",
        );
        assert_corrupt(&archive, "numblocks");
        // 0.0: a numbytes with no offset.
        let archive = pax_entry(
            &[("GNU.sparse.size", b"100"), ("GNU.sparse.numbytes", b"5")],
            "f",
            b"hello",
        );
        assert_corrupt(&archive, "no `offset`");
    }

    /// A map listing more regions than the ceiling is exit 6, before the
    /// list grows past it.
    #[test]
    fn a_map_past_the_region_ceiling_is_a_resource_limit() {
        let count = MAX_SPARSE_REGIONS + 1;
        let mut payload = format!("{count}\n").into_bytes();
        payload.extend("0\n0\n".repeat(count as usize).as_bytes());
        payload.resize(payload.len().div_ceil(BLOCK) * BLOCK, 0);
        match error_of(&v1("f", 100, &payload)) {
            Error::ResourceLimit(m) => assert!(m.contains("regions"), "{m}"),
            other => panic!("{other:?}"),
        }
        let map = "0,0,".repeat(count as usize);
        match error_of(&v0_1(map.trim_end_matches(','), 100, b"")) {
            Error::ResourceLimit(m) => assert!(m.contains("regions"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// A later version is refused as unsupported (exit 3), naming it.
    #[test]
    fn an_unknown_sparse_version_is_unsupported() {
        let archive = pax_entry(
            &[
                ("GNU.sparse.major", b"2"),
                ("GNU.sparse.minor", b"0"),
                ("GNU.sparse.name", b"f"),
                ("GNU.sparse.realsize", b"10"),
            ],
            "GNUSparseFile.0/f",
            b"",
        );
        match error_of(&archive) {
            Error::Unsupported(m) => assert!(m.contains("2.0"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// A huge real size over a tiny payload lists at its real size and
    /// costs nothing to describe; reading it is the verb's budget's call.
    #[test]
    fn a_huge_real_size_is_listed_without_reading() {
        let archive = v1("f", 1 << 50, &v1_payload(&[(0, b"x")]));
        let mut ar = open_pipe(&archive);
        let entry = ar.next_entry().unwrap().unwrap();
        assert_eq!(entry.meta().name, "f");
        assert_eq!(entry.meta().size, Some(1 << 50));
    }

    #[test]
    fn pax_times_parse_signed_and_fractional() {
        let at = |s: i64, n: u32| {
            if s >= 0 {
                TimeField::Known(UNIX_EPOCH + Duration::new(s as u64, n))
            } else {
                TimeField::Known(UNIX_EPOCH - Duration::new(s.unsigned_abs(), n))
            }
        };
        assert_eq!(pax_time(b"20000000000"), at(20_000_000_000, 0));
        assert_eq!(pax_time(b"-31536000"), at(-31_536_000, 0));
        assert_eq!(
            pax_time(b"1794784461.013422541"),
            at(1_794_784_461, 13_422_541)
        );
        assert_eq!(pax_time(b"1.5"), at(1, 500_000_000));
        assert_eq!(pax_time(b"-1.5"), at(-1, 500_000_000));
        for bad in [
            &b""[..],
            b"-",
            b"x",
            b"1.2.3",
            b"1e9",
            b" 1",
            b"99999999999999999999999",
        ] {
            assert_eq!(pax_time(bad), TimeField::Unusable, "{bad:?}");
        }
    }

    fn one_entry_report(bytes: &[u8]) -> (Option<SystemTime>, Vec<Fidelity>) {
        let mut ar = open_pipe(bytes);
        let mtime = {
            let entry = ar.next_entry().unwrap().unwrap();
            entry.meta().mtime
        };
        while ar.next_entry().unwrap().is_some() {}
        (mtime, ar.fidelity().warnings.clone())
    }

    /// Finding 25: the pax `mtime` record wins over the header field, which a
    /// writer leaves 0 for a time it cannot hold.
    #[test]
    fn the_pax_mtime_record_wins_over_the_header_field() {
        for (value, secs) in [
            ("20000000000", 20_000_000_000i64),
            ("-31536000", -31_536_000),
        ] {
            let archive = pax_entry(&[("mtime", value.as_bytes())], "f", b"data");
            let (mtime, warnings) = one_entry_report(&archive);
            let want = if secs >= 0 {
                UNIX_EPOCH + Duration::from_secs(secs as u64)
            } else {
                UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
            };
            assert_eq!(mtime, Some(want), "{value}");
            assert!(warnings.is_empty(), "{warnings:?}");
        }
    }

    fn mtime_lost(warnings: &[Fidelity]) -> bool {
        warnings
            .iter()
            .any(|w| matches!(w, Fidelity::MetadataIncomplete { entry, fields } if entry == "f" && fields.mtime))
    }

    /// A pax mtime that cannot be read, or one no `SystemTime` holds, is a
    /// reported loss, never silently 1970 or "now". The header's own field,
    /// when it holds a time, is the fallback (task 4 review, minor 2): the
    /// pax record's precision is what is lost, not the time.
    #[test]
    fn an_unusable_mtime_is_reported() {
        let header = Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let archive = pax_entry(&[("mtime", b"soon")], "f", b"data");
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, header);
        assert!(mtime_lost(&warnings), "{warnings:?}");

        let huge = format!("{}", u64::MAX);
        let archive = pax_entry(&[("mtime", huge.as_bytes())], "f", b"data");
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, header);
        assert!(mtime_lost(&warnings), "{warnings:?}");

        // With the header's field unusable too, the mtime is unknown.
        let mut archive = pax_entry(&[("mtime", b"soon")], "f", b"data");
        let at = archive.len() - 3 * BLOCK - BLOCK;
        set_header_mtime(&mut archive[at..at + BLOCK], *b"zzzzzzzzzzz\0");
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, None);
        assert!(mtime_lost(&warnings), "{warnings:?}");
    }

    /// The header's `mtime` field set to `field`, its checksum re-summed.
    fn set_header_mtime(header: &mut [u8], field: [u8; 12]) {
        header[136..148].copy_from_slice(&field);
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    /// An empty header `mtime` field (all NUL, or blanks) is no time at all:
    /// read as 0, as bsdtar reads it (`tar -tvf` shows 1970 and `-x` sets
    /// it), and not reported (task 4 review, minor 1). Garbage is still a
    /// reported loss.
    #[test]
    fn an_empty_header_mtime_is_the_epoch_and_not_reported() {
        for field in [[0u8; 12], *b"           \0", [b' '; 12]] {
            let mut archive = pax_entry(&[], "f", b"data");
            set_header_mtime(&mut archive[..BLOCK], field);
            let (mtime, warnings) = one_entry_report(&archive);
            assert_eq!(mtime, Some(UNIX_EPOCH), "{field:?}");
            assert!(warnings.is_empty(), "{field:?}: {warnings:?}");
        }
        let mut archive = pax_entry(&[], "f", b"data");
        set_header_mtime(&mut archive[..BLOCK], *b"zzzzzzzzzzz\0");
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, None);
        assert!(mtime_lost(&warnings), "{warnings:?}");
    }

    /// A GNU base-256 negative header mtime (GNU tar's pre-1970 spelling) is
    /// read as the time before the epoch it names.
    #[test]
    fn a_gnu_negative_header_mtime_is_read() {
        let mut archive = pax_entry(&[], "f", b"data");
        let header = &mut archive[..BLOCK];
        // -31536000 as twelve bytes of two's complement.
        let mut field = [0xffu8; 12];
        field[4..].copy_from_slice(&(-31_536_000i64).to_be_bytes());
        header[136..148].copy_from_slice(&field);
        // Re-sum the checksum.
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, Some(UNIX_EPOCH - Duration::from_secs(31_536_000)));
        assert!(warnings.is_empty(), "{warnings:?}");

        // A base-256 value no i64 holds is unknown, and reported.
        let mut archive = pax_entry(&[], "f", b"data");
        let header = &mut archive[..BLOCK];
        let mut field = [0xffu8; 12];
        field[0..4].copy_from_slice(&[0xff, 0x00, 0x00, 0x00]);
        header[136..148].copy_from_slice(&field);
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let (mtime, warnings) = one_entry_report(&archive);
        assert_eq!(mtime, None);
        assert!(mtime_lost(&warnings), "{warnings:?}");
    }
}
