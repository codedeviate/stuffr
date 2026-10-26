//! The writing half of `zipfile.c`: the local header (`putlocal`), the data
//! descriptor (`putextended`), the central header (`putcentral`), the end
//! records (`putend`, with the Zip64 end record and locator), the Zip64
//! extra fields, and `fileio.c`'s `bfwrite`, which every one of them goes
//! through and which keeps the offsets and the central directory's counts.
//!
//! Each record is built in memory and written whole, as the C's
//! `append_*_to_mem` and one `bfwrite` do; a local header is rewritten in
//! place ([`ZWrite::seek_to`], [`ZWrite::write_here`], [`ZWrite::seek_end`]) once its sizes and CRC are known, unless
//! the archive cannot be rewound (a pipe) or `-fd` asks for data
//! descriptors.
//!
//! Splits (`-s`, `-sp`): `bfwrite` moves to the next split where one is
//! full (`split.rs` keeps the splits).

use std::io::{self, Write};

/// zip.h:LOCSIG and friends.
const LOCSIG: u32 = 0x0403_4b50;
const CENSIG: u32 = 0x0201_4b50;
const ENDSIG: u32 = 0x0605_4b50;
const EXTLOCSIG: u32 = 0x0807_4b50;
const ZIP64_CENTRAL_DIR_TAIL_SIG: u32 = 0x0606_4b50;
const ZIP64_CENTRAL_DIR_TAIL_END_SIG: u32 = 0x0706_4b50;
/// zipfile.c: `56 - 8 - 4`, the Zip64 end record's size field.
const ZIP64_CENTRAL_DIR_TAIL_SIZE: u64 = 56 - 8 - 4;
/// zipfile.c:ZIP64_MIN_VER
pub(crate) const ZIP64_MIN_VER: u16 = 45;
/// zipfile.c:ZIP64_EF_TAG
const ZIP64_EF_TAG: u16 = 0x0001;
/// zipfile.c:ZIP_EF_HEADER_SIZE
const ZIP_EF_HEADER_SIZE: usize = 4;
const ZIP_UWORD32_MAX: u64 = 0xffff_ffff;
const ZIP_UWORD16_MAX: u64 = 0xffff;
/// zip.h: the fixed part of a local header after its signature.
pub(crate) const LOCHEAD: u64 = 26;
/// zip.h: the fixed part of a central header after its signature.
pub(crate) const CENHEAD: u64 = 42;

/// One archive entry as zip writes it: the fields of `struct zlist` that
/// the headers carry (zip.h), with the C's names.
#[derive(Debug, Clone, Default)]
pub(crate) struct ZEntry {
    /// The name on disk (`z->name`): `-m` deletes it, messages show it.
    pub(crate) name: Vec<u8>,
    /// The stored name (`z->iname`; `z->zname` is the same on unix).
    pub(crate) iname: Vec<u8>,
    /// The name messages show (`z->oname`).
    pub(crate) oname: Vec<u8>,
    /// Version made by.
    pub(crate) vem: u16,
    /// Version needed to extract.
    pub(crate) ver: u16,
    /// General-purpose flags of the central header.
    pub(crate) flg: u16,
    /// General-purpose flags of the local header.
    pub(crate) lflg: u16,
    /// Compression method.
    pub(crate) how: u16,
    /// MS-DOS time and date.
    pub(crate) tim: u32,
    pub(crate) crc: u32,
    /// Compressed size.
    pub(crate) siz: u64,
    /// Uncompressed size.
    pub(crate) len: u64,
    /// The local extra field (`extra`, `ext`).
    pub(crate) extra: Vec<u8>,
    /// The central extra field (`cextra`, `cext`).
    pub(crate) cextra: Vec<u8>,
    /// The entry comment (`comment`, `com`).
    pub(crate) comment: Vec<u8>,
    /// The disk the local header is on.
    pub(crate) dsk: u64,
    /// Internal attributes (bit 0: text).
    pub(crate) att: u16,
    /// External attributes.
    pub(crate) atx: u32,
    /// Offset of the local header.
    pub(crate) off: u64,
}

/// Where an archive is written: a file (the temporary archive, or standard
/// output when it is one) that can be rewound to rewrite a local header,
/// or a stream that cannot (a pipe).
pub(crate) trait ZWrite: Write {
    /// Whether a local header can be rewritten (`is_seekable(y)`).
    fn seekable(&self) -> bool;
    /// Bytes written so far: the offset of the next one.
    fn offset(&self) -> u64;
    /// `zfseeko(y, at, SEEK_SET)`, which flushes the stream first: an
    /// error is the seek failing (zip then writes a data descriptor).
    fn seek_to(&mut self, at: u64) -> io::Result<()>;
    /// `fwrite` where the stream is, outside `bfwrite`'s count (the local
    /// header's rewrite).
    fn write_here(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// `zfseeko(y, bytes_this_split, SEEK_SET)`: back to the end.
    fn seek_end(&mut self) -> io::Result<()>;
    /// zipup.c:seekable's `fseeko(y, ftello(y), SEEK_SET)`: flush and stay
    /// where the stream really is (an absolute position: standard output
    /// may have started past 0).
    fn seek_here(&mut self) -> io::Result<()>;
    /// `ferror(y)`: the error a write of the stream met (sticky, as stdio's
    /// error flag), with the `errno` it left.
    fn ferror(&self) -> Option<io::Error>;
    /// `zfseeko(y, at, SEEK_SET)` that leaves `bytes_this_split` (the
    /// count [`ZWrite::offset`] gives) as it is: `-F`/`-FF` move back over
    /// an entry they drop and write the next over it.
    fn seek_raw(&mut self, _at: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(29))
    }
    /// `zftello(y)`: where the stream really is.
    fn tell_raw(&mut self) -> io::Result<u64> {
        Err(io::Error::from_raw_os_error(29))
    }
    /// `bytes_this_split = at`.
    fn set_offset(&mut self, _at: u64) {}
}

/// What `bfwrite` is writing (fileio.c's `BFWRITE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bf {
    /// File data: counted in `bytes_this_entry`.
    Data,
    /// A local header: its offset is remembered.
    LocalHeader,
    /// A central header: counted in the end record.
    CentralHeader,
    /// Any other record (a descriptor, the end records).
    Header,
}

/// `-dg`'s dots: printed per archive as `bfwrite` writes, not per file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GlobalDots {
    pub(crate) dot_size: i64,
    pub(crate) dot_count: i64,
}

/// What `bfwrite` printed to `mesg` (or rang) where its caller holds the
/// message layer, passed on in order by `zipup::drain_dots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pend {
    /// `-dg`'s dots and their leading space (a dot starts a line).
    Dots(Vec<u8>),
    /// `fprintf(mesg, ...)`: written as it is, the line state untouched.
    Raw(Vec<u8>),
    /// `if (mesg_line_started) fprintf(mesg, "\n")`.
    NlIfLine,
    /// `zipmessage(text, "")`.
    Message(Vec<u8>),
    /// A `zipmessage` already written to `mesg` (before a question): its
    /// log copy.
    LogOnly(Vec<u8>),
}

/// The archive being written and `bfwrite`'s globals (fileio.c, zip.c).
pub(crate) struct ZOut {
    /// `y`: the archive, or the split being written.
    pub(crate) w: Box<dyn ZWrite>,
    /// `bytes_this_entry`: data bytes of the current entry.
    pub(crate) bytes_this_entry: u64,
    /// `current_local_offset`
    pub(crate) current_local_offset: u64,
    /// `current_local_disk`: the split the last local header went to.
    pub(crate) current_local_disk: u64,
    /// `current_disk`: the split being written (0 without splits).
    pub(crate) current_disk: u64,
    /// `bytes_prev_splits`
    pub(crate) bytes_prev_splits: u64,
    /// `cd_start_disk` and `cd_start_offset`, once the first central header
    /// is written.
    cd_start: Option<(u64, u64)>,
    /// `cd_entries_this_disk`
    pub(crate) cd_entries_this_disk: u64,
    /// `total_cd_entries`
    total_cd_entries: u64,
    /// `zip64_entry`: the current entry's headers use Zip64.
    pub(crate) zip64_entry: bool,
    /// `zip64_archive`: an entry needed Zip64.
    pub(crate) zip64_archive: bool,
    /// `-fz` (1), `-fz-` (0), neither (-1).
    pub(crate) force_zip64: i8,
    /// `-dg`'s state, when it is on.
    pub(crate) gdots: Option<GlobalDots>,
    /// What `bfwrite` printed that the caller has not yet passed to `mesg`.
    pub(crate) pending: Vec<Pend>,
    /// `-s`/`-sp`: the splits (`split_method` 1 or 2), when splitting.
    pub(crate) split: Option<Box<super::split::SplitW>>,
    /// `split_size`, also when not splitting (`-s 64k -s-`: what does not
    /// fit is not written, as in the C).
    pub(crate) split_size: u64,
}

impl ZOut {
    pub(crate) fn new(w: Box<dyn ZWrite>, force_zip64: i8, gdots: Option<GlobalDots>) -> ZOut {
        ZOut {
            w,
            bytes_this_entry: 0,
            current_local_offset: 0,
            current_local_disk: 0,
            current_disk: 0,
            bytes_prev_splits: 0,
            cd_start: None,
            cd_entries_this_disk: 0,
            total_cd_entries: 0,
            zip64_entry: false,
            zip64_archive: false,
            force_zip64,
            gdots,
            pending: Vec::new(),
            split: None,
            split_size: 0,
        }
    }

    /// zipsplit.c:main, the start of each output file: the archive is now
    /// `w`, from its first byte, with no central directory written yet.
    /// What outlives one file (`zip64_archive`, the force flags) stays, as
    /// the C's globals do.
    pub(crate) fn restart(&mut self, w: Box<dyn ZWrite>) {
        self.w = w;
        self.bytes_this_entry = 0;
        self.current_local_offset = 0;
        self.current_local_disk = 0;
        self.current_disk = 0;
        self.bytes_prev_splits = 0;
        self.cd_start = None;
        self.cd_entries_this_disk = 0;
        self.total_cd_entries = 0;
        self.pending.clear();
    }

    /// The dots `bfwrite` has printed and not yet passed on (tests).
    #[cfg(test)]
    pub(crate) fn pending_dots(&self) -> Vec<u8> {
        let mut d = Vec::new();
        for p in &self.pending {
            if let Pend::Dots(b) = p {
                d.extend_from_slice(b);
            }
        }
        d
    }

    fn dot(&mut self, c: u8) {
        if let Some(Pend::Dots(d)) = self.pending.last_mut() {
            d.push(c);
        } else {
            self.pending.push(Pend::Dots(vec![c]));
        }
    }

    /// fileio.c:bfwrite: writes `b`, keeps the counts, and with splits
    /// moves to the next split where this one is full (a header is never
    /// split: it goes whole to the next); `-dg` prints its dots here.
    // port: fileio.c:bfwrite
    pub(crate) fn bfwrite(&mut self, b: &[u8], mode: Bf) -> io::Result<()> {
        if mode == Bf::LocalHeader {
            self.bytes_this_entry = 0;
            // the local header's split is the current one from now on
            if let Some(s) = self.split.as_mut() {
                s.local_header_starts();
            }
            self.current_local_disk = self.current_disk;
            self.current_local_offset = self.w.offset();
        }
        let header = mode != Bf::Data;
        let split_size = self.split_size;
        let left = if split_size == 0 {
            b.len() as u64
        } else {
            split_size.saturating_sub(self.w.offset())
        };
        let mut to_write = b.len();
        if to_write as u64 > left {
            // a header that does not fit goes whole to the next split; data
            // fills this one
            to_write = if header { 0 } else { left as usize };
        }
        if mode == Bf::CentralHeader {
            if self.cd_start.is_none() {
                self.cd_start = Some((self.current_disk, self.w.offset()));
            }
            self.cd_entries_this_disk += 1;
            self.total_cd_entries += 1;
        }
        let mut written = 0usize;
        let mut result = Ok(());
        if to_write > 0 {
            match self.w.write_all(&b[..to_write]) {
                Ok(()) => written = to_write,
                Err(e) => result = Err(e),
            }
            if mode == Bf::Data {
                self.bytes_this_entry += written as u64;
            }
        }
        // without splits the rest is not written (a write error is
        // `ferror(y)`'s, answered by the caller)
        if written < b.len() && self.split.is_some() {
            result = self.next_split(&b[written..], mode, result.err());
        }
        // display dots for the archive instead of for each file
        if let Some(mut g) = self.gdots {
            if g.dot_size > 0 {
                if g.dot_count == -1 {
                    self.dot(b' ');
                    // assume a header will be written first, so avoid 0
                    g.dot_count = 1;
                }
                // skip incrementing the count for small buffers (headers)
                if b.len() > 1000 {
                    g.dot_count += 1;
                    if g.dot_size <= g.dot_count.saturating_mul(b.len() as i64) {
                        g.dot_count = 0;
                    }
                }
            }
            if g.dot_size != 0 && g.dot_count == 0 {
                g.dot_count += 1;
                self.dot(b'.');
            }
            self.gdots = Some(g);
        }
        result
    }

    /// The end record's disk fields: `current_disk`, `cd_start_disk` (0
    /// when no central header was written), `cd_start_offset`.
    fn end_disks(&self) -> (u64, u64, u64) {
        let (d, o) = self.cd_start.unwrap_or((0, 0));
        (self.current_disk, d, o)
    }
}

fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// zipfile.c:get_extra_field: the offset of the block tagged `tag` in
/// `extra`, if any.
// port: zipfile.c:get_extra_field
fn get_extra_field(tag: u16, extra: &[u8]) -> Option<usize> {
    let mut p = 0usize;
    // `for (p = extra; p < extra + len - 4;)`
    while p + ZIP_EF_HEADER_SIZE < extra.len() {
        let block_tag = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let size = u16::from_le_bytes([extra[p + 2], extra[p + 3]]);
        if block_tag == tag {
            return Some(p);
        }
        p += usize::from(size) + ZIP_EF_HEADER_SIZE;
    }
    None
}

/// zipfile.c:add_local_zip64_extra_field: the local Zip64 block (both
/// sizes) added after the other blocks, or updated where it is.
// port: zipfile.c:add_local_zip64_extra_field
fn add_local_zip64_extra_field(z: &mut ZEntry) {
    const Z64_LOCAL_LEN: usize = ZIP_EF_HEADER_SIZE + 8 + 8;
    let at = match get_extra_field(ZIP64_EF_TAG, &z.extra) {
        None => {
            let at = z.extra.len();
            z.extra.resize(at + Z64_LOCAL_LEN, 0);
            at
        }
        Some(old) => {
            let size = usize::from(u16::from_le_bytes([z.extra[old + 2], z.extra[old + 3]]));
            if size == Z64_LOCAL_LEN - ZIP_EF_HEADER_SIZE {
                old
            } else {
                // drop the old block and add one of the right size where it
                // was, before what followed it
                let end = (old + ZIP_EF_HEADER_SIZE + size).min(z.extra.len());
                let tail = z.extra.split_off(end);
                z.extra.truncate(old);
                let at = z.extra.len();
                z.extra.resize(at + Z64_LOCAL_LEN, 0);
                z.extra.extend_from_slice(&tail);
                at
            }
        }
    };
    let mut b = Vec::with_capacity(Z64_LOCAL_LEN);
    put16(&mut b, ZIP64_EF_TAG);
    put16(&mut b, (Z64_LOCAL_LEN - ZIP_EF_HEADER_SIZE) as u16);
    put64(&mut b, z.len);
    put64(&mut b, z.siz);
    z.extra[at..at + Z64_LOCAL_LEN].copy_from_slice(&b);
}

/// zipfile.c:add_central_zip64_extra_field: the central Zip64 block, with
/// the fields that do not fit (and the uncompressed size under `-fz`).
/// `Err(())` is `ZE_BIG` under `-fz-`.
// port: zipfile.c:add_central_zip64_extra_field
fn add_central_zip64_extra_field(z: &mut ZEntry, force_zip64: i8) -> Result<(), ()> {
    let mut efsize = ZIP_EF_HEADER_SIZE;
    let mut used = false;
    if z.len > ZIP_UWORD32_MAX || force_zip64 == 1 {
        efsize += 8;
        used = true;
    }
    if z.siz > ZIP_UWORD32_MAX {
        efsize += 8;
        used = true;
    }
    if z.off > ZIP_UWORD32_MAX {
        efsize += 8;
        used = true;
    }
    if z.dsk > ZIP_UWORD16_MAX {
        efsize += 4;
        used = true;
    }
    if used && force_zip64 == 0 {
        return Err(());
    }
    let at = if z.cextra.is_empty() {
        if efsize == ZIP_EF_HEADER_SIZE {
            return Ok(());
        }
        z.cextra.resize(efsize, 0);
        0
    } else {
        match get_extra_field(ZIP64_EF_TAG, &z.cextra) {
            None => {
                let at = z.cextra.len();
                z.cextra.resize(at + efsize, 0);
                at
            }
            Some(old) => {
                let size = usize::from(u16::from_le_bytes([z.cextra[old + 2], z.cextra[old + 3]]));
                let oldefsize = size + ZIP_EF_HEADER_SIZE;
                if z.cextra.len() == oldefsize {
                    // only the Zip64 block
                    z.cextra.resize(efsize, 0);
                    0
                } else {
                    // take the old block out and add the new one at the end
                    let end = (old + oldefsize).min(z.cextra.len());
                    z.cextra.drain(old..end);
                    let at = z.cextra.len();
                    z.cextra.resize(at + efsize, 0);
                    at
                }
            }
        }
    };
    let mut b = Vec::with_capacity(efsize);
    put16(&mut b, ZIP64_EF_TAG);
    put16(&mut b, (efsize - ZIP_EF_HEADER_SIZE) as u16);
    if z.len > ZIP_UWORD32_MAX || force_zip64 == 1 {
        put64(&mut b, z.len);
    }
    if z.siz > ZIP_UWORD32_MAX {
        put64(&mut b, z.siz);
    }
    if z.off > ZIP_UWORD32_MAX {
        put64(&mut b, z.off);
    }
    if z.dsk > ZIP_UWORD16_MAX {
        put32(&mut b, z.dsk as u32);
    }
    z.cextra[at..at + efsize].copy_from_slice(&b);
    Ok(())
}

/// Why a header could not be written: `ZE_BIG` with zip's warning and
/// message, or a failed write.
#[derive(Debug)]
pub(crate) enum PutError {
    /// `zipwarn(warn, oname)` (when `warn` is not empty), then
    /// `ZIPERR(ZE_BIG, why)`.
    Big {
        warn: &'static str,
        why: &'static str,
    },
    /// The write failed (`bfwrite`'s `ZE_WRITE`).
    Write(io::Error),
}

/// The local header of `z` as `putlocal` builds it, Zip64 decided as it
/// decides (`rewrite`: the second write, once the sizes are known), or the
/// error it ends the run with.
// port: zipfile.c:putlocal
fn local_header(z: &mut ZEntry, out: &mut ZOut, rewrite: bool) -> Result<Vec<u8>, PutError> {
    use super::messages as m;
    // standard input is streamed: its size is not known in advance
    let streaming_in = z.name == b"-";
    let force = out.force_zip64;
    let needs = z.siz > ZIP_UWORD32_MAX
        || z.len > ZIP_UWORD32_MAX
        || force == 1
        || (force != 0 && streaming_in);
    let mut was_zip64 = false;
    if !rewrite {
        out.zip64_entry = false;
        if needs {
            if force == 0 {
                return Err(PutError::Big {
                    warn: m::ENTRY_TOO_BIG,
                    why: m::LARGE_DISABLED_NEEDED,
                });
            }
            out.zip64_entry = true;
            if z.ver < ZIP64_MIN_VER {
                z.ver = ZIP64_MIN_VER;
            }
            was_zip64 = true;
        }
    } else {
        was_zip64 = out.zip64_entry;
        out.zip64_entry = needs;
        if force == 0 && out.zip64_entry {
            return Err(PutError::Big {
                warn: m::ENTRY_TOO_BIG,
                why: m::LARGE_DISABLED_ENTRY_NEEDS,
            });
        }
        if !was_zip64 && out.zip64_entry {
            return Err(PutError::Big {
                warn: m::ENTRY_TOO_BIG,
                why: if force == 0 {
                    m::UNEXPECTEDLY_LARGE
                } else {
                    m::POOR_COMPRESSION
                },
            });
        }
        if out.zip64_entry {
            out.zip64_archive = true;
            if z.ver < ZIP64_MIN_VER {
                z.ver = ZIP64_MIN_VER;
            }
        }
        if was_zip64 && !out.zip64_entry {
            z.ver = 20;
        }
    }
    if out.zip64_entry || was_zip64 {
        add_local_zip64_extra_field(z);
    }
    // Task 11: Ubuntu's UTF-8 flag and Unicode path field go here.
    let mut b = Vec::with_capacity(30 + z.iname.len() + z.extra.len());
    put32(&mut b, LOCSIG);
    put16(&mut b, z.ver);
    put16(&mut b, z.lflg);
    put16(&mut b, z.how);
    put32(&mut b, z.tim);
    put32(&mut b, z.crc);
    if out.zip64_entry {
        put32(&mut b, 0xffff_ffff);
        put32(&mut b, 0xffff_ffff);
    } else {
        put32(&mut b, z.siz as u32);
        put32(&mut b, z.len as u32);
    }
    put16(&mut b, z.iname.len() as u16);
    put16(&mut b, z.extra.len() as u16);
    b.extend_from_slice(&z.iname);
    b.extend_from_slice(&z.extra);
    Ok(b)
}

/// zipfile.c:putlocal, the first write (`PUTLOCAL_WRITE`, through
/// `bfwrite`, which remembers where it is).
pub(crate) fn putlocal(z: &mut ZEntry, out: &mut ZOut) -> Result<(), PutError> {
    let b = local_header(z, out, false)?;
    out.bfwrite(&b, Bf::LocalHeader).map_err(PutError::Write)
}

/// zipfile.c:putlocal, the rewrite (`PUTLOCAL_REWRITE`): `fwrite` over
/// the first, where the caller has seeked (`z.off`).
pub(crate) fn putlocal_rewrite(z: &mut ZEntry, out: &mut ZOut) -> Result<(), PutError> {
    let b = local_header(z, out, true)?;
    if out.split.as_ref().is_some_and(|s| s.method == 1) {
        // also when splitting: to the split with the local header, which
        // can be closed now if it is not the current one
        return out.rewrite_in_local_split(&b).map_err(PutError::Write);
    }
    out.w.write_here(&b).map_err(PutError::Write)
}

/// zipfile.c:putextended: the data descriptor (Zip64 sizes when the entry
/// is Zip64).
// port: zipfile.c:putextended
pub(crate) fn putextended(z: &ZEntry, out: &mut ZOut) -> io::Result<()> {
    let mut b = Vec::with_capacity(24);
    put32(&mut b, EXTLOCSIG);
    put32(&mut b, z.crc);
    if out.zip64_entry {
        put64(&mut b, z.siz);
        put64(&mut b, z.len);
    } else {
        put32(&mut b, z.siz as u32);
        put32(&mut b, z.len as u32);
    }
    out.bfwrite(&b, Bf::Header)
}

/// zipfile.c:putcentral: the central header of `z` (its Zip64 block added
/// first when a field does not fit or `-fz` asks).
// port: zipfile.c:putcentral
pub(crate) fn putcentral(z: &mut ZEntry, out: &mut ZOut) -> Result<(), PutError> {
    // Task 11: Ubuntu's UTF-8 flag and Unicode path field go here.
    if (z.siz > ZIP_UWORD32_MAX
        || z.len > ZIP_UWORD32_MAX
        || z.off > ZIP_UWORD32_MAX
        || z.dsk > ZIP_UWORD16_MAX
        || out.force_zip64 == 1)
        && add_central_zip64_extra_field(z, out.force_zip64).is_err()
    {
        return Err(PutError::Big {
            warn: "",
            why: super::messages::LARGE_DISABLED_USING,
        });
    }
    let mut b = Vec::with_capacity(46 + z.iname.len() + z.cextra.len() + z.comment.len());
    put32(&mut b, CENSIG);
    put16(&mut b, z.vem);
    put16(&mut b, z.ver);
    put16(&mut b, z.flg);
    put16(&mut b, z.how);
    put32(&mut b, z.tim);
    put32(&mut b, z.crc);
    put32(&mut b, z.siz.min(ZIP_UWORD32_MAX) as u32);
    if z.len > ZIP_UWORD32_MAX || out.force_zip64 == 1 {
        put32(&mut b, 0xffff_ffff);
    } else {
        put32(&mut b, z.len as u32);
    }
    put16(&mut b, z.iname.len() as u16);
    put16(&mut b, z.cextra.len() as u16);
    put16(&mut b, z.comment.len() as u16);
    put16(&mut b, z.dsk.min(ZIP_UWORD16_MAX) as u16);
    put16(&mut b, z.att);
    put32(&mut b, z.atx);
    put32(&mut b, z.off.min(ZIP_UWORD32_MAX) as u32);
    b.extend_from_slice(&z.iname);
    b.extend_from_slice(&z.cextra);
    b.extend_from_slice(&z.comment);
    out.bfwrite(&b, Bf::CentralHeader).map_err(PutError::Write)
}

/// zipfile.c:putend: the end of central directory record, after the Zip64
/// end record and locator when the archive needs them. `n` entries, a
/// central directory of `s` bytes at `c`, the archive comment.
// port: zipfile.c:putend
pub(crate) fn putend(out: &mut ZOut, n: u64, s: u64, c: u64, comment: &[u8]) -> io::Result<()> {
    putend_with(out, n, s, c, comment.len(), comment)
}

/// [`putend`] with the comment's length `m` given apart: `-FF` keeps the
/// length of a comment it could not read (`zcomlen`) and writes no bytes
/// for it (`append_string_to_mem` of NULL).
pub(crate) fn putend_with(
    out: &mut ZOut,
    n: u64,
    s: u64,
    c: u64,
    m: usize,
    comment: &[u8],
) -> io::Result<()> {
    let (current_disk, cd_start_disk, cd_start_offset) = out.end_disks();
    let zip64_eocd_disk = current_disk;
    let zip64_eocd_offset = out.w.offset();
    let mut b = Vec::with_capacity(98 + comment.len());
    if n > ZIP_UWORD16_MAX || s > ZIP_UWORD32_MAX || c > ZIP_UWORD32_MAX || out.zip64_archive {
        put32(&mut b, ZIP64_CENTRAL_DIR_TAIL_SIG);
        put64(&mut b, ZIP64_CENTRAL_DIR_TAIL_SIZE);
        // version made by: OS_CODE + Z_MAJORVER * 10 + Z_MINORVER
        put16(&mut b, 0x300 + 30);
        put16(&mut b, ZIP64_MIN_VER);
        put32(&mut b, current_disk as u32);
        put32(&mut b, cd_start_disk as u32);
        put64(&mut b, out.cd_entries_this_disk);
        put64(&mut b, n);
        put64(&mut b, s);
        put64(&mut b, cd_start_offset);
        put32(&mut b, ZIP64_CENTRAL_DIR_TAIL_END_SIG);
        put32(&mut b, zip64_eocd_disk as u32);
        put64(&mut b, zip64_eocd_offset);
        put32(&mut b, (current_disk + 1) as u32);
    }
    put32(&mut b, ENDSIG);
    put16(&mut b, current_disk.min(0xffff) as u16);
    put16(&mut b, cd_start_disk.min(0xffff) as u16);
    put16(&mut b, out.cd_entries_this_disk.min(0xffff) as u16);
    put16(&mut b, out.total_cd_entries.min(0xffff) as u16);
    put32(&mut b, s.min(ZIP_UWORD32_MAX) as u32);
    if out.force_zip64 == 1 || cd_start_offset > ZIP_UWORD32_MAX {
        put32(&mut b, 0xffff_ffff);
    } else {
        put32(&mut b, cd_start_offset as u32);
    }
    put16(&mut b, m as u16);
    b.extend_from_slice(comment);
    out.bfwrite(&b, Bf::Header)
}

/// What [`write_central`] wrote: zip.c's `n` (uncompressed bytes), `t`
/// (compressed bytes) and `k` (entries) for `-v`'s totals and the empty
/// warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) n: u64,
    pub(crate) t: u64,
    pub(crate) k: u64,
}

/// zip.c:main, "Write central directory and end header": a central header
/// for each of `entries`, then `before_end` (the C prints the empty
/// warning and `-v`'s totals there), then the end records with the archive
/// `comment`. `tempzn` is zip's running count of bytes written, kept.
// port: zip.c:main (the central directory and putend)
pub(crate) fn write_central(
    entries: &mut [ZEntry],
    comment: &[u8],
    out: &mut ZOut,
    tempzn: &mut u64,
    before_end: &mut dyn FnMut(&mut ZOut, Totals),
) -> Result<Totals, PutError> {
    let c = *tempzn;
    let mut tot = Totals { n: 0, t: 0, k: 0 };
    for e in entries.iter_mut() {
        putcentral(e, out)?;
        *tempzn +=
            4 + CENHEAD + e.iname.len() as u64 + e.cextra.len() as u64 + e.comment.len() as u64;
        // an old entry's declared sizes wrap as the C's uzoff_t
        tot.n = tot.n.wrapping_add(e.len);
        tot.t = tot.t.wrapping_add(e.siz);
        tot.k += 1;
    }
    before_end(out, tot);
    let size = *tempzn - c;
    putend(out, tot.k, size, c, comment).map_err(PutError::Write)?;
    Ok(tot)
}

#[cfg(test)]
mod tests;
