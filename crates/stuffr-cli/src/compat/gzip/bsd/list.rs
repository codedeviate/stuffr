//! `-l`'s pieces that are not `print_list` itself (which is in
//! `run/decompress.rs`, beside the run's state): `ctime`'s fields as `-lv`
//! prints them, and `unxz_len`, the uncompressed size of an `.xz` file
//! from its indexes.
//!
//! `unxz_len` is `file_cmds-479` `gzip/unxz.c`'s `parse_indexes` (copied
//! there from xz's `list.c`, public domain) over liblzma's index and
//! stream-flag decoders, written here for the checks they make: the file
//! is read backwards a stream at a time, past stream padding, through the
//! footer, the index (its records' sizes summed) and the header, and any
//! failure makes the size 0. The state is a few integers whatever the
//! number of records.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

/// `ctime(&ts) + 4` cut at 12 bytes: `"Sep  9 01:46"`, local time.
pub(super) fn ctime_short(ts: i64) -> String {
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (mon, mday, hour, min) = local_fields(ts);
    format!("{} {mday:2} {hour:02}:{min:02}", MON[mon.min(11) as usize])
}

/// Month (0-11), day, hour and minute of `ts` in local time.
#[cfg(unix)]
fn local_fields(ts: i64) -> (i32, i32, i32, i32) {
    let t = ts as libc::time_t;
    // SAFETY: `tm` is plain data, fully written by a successful
    // `localtime_r`; both pointers are valid for the call.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if ok {
        (tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min)
    } else {
        utc_fields(ts)
    }
}

#[cfg(not(unix))]
fn local_fields(ts: i64) -> (i32, i32, i32, i32) {
    utc_fields(ts)
}

/// The same in UTC (days from the civil calendar).
fn utc_fields(ts: i64) -> (i32, i32, i32, i32) {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        (m - 1) as i32,
        d as i32,
        (secs / 3600) as i32,
        (secs / 60 % 60) as i32,
    )
}

const HEADER_SIZE: u64 = 12;
const HEADER_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
/// `IO_BUFFER_SIZE` (`BUFSIZ & ~7`, or 8192 when `BUFSIZ` is small).
const IO_BUFFER_SIZE: usize = 8192;
const VLI_MAX: u64 = u64::MAX / 2;
const UNPADDED_SIZE_MIN: u64 = 5;
const UNPADDED_SIZE_MAX: u64 = VLI_MAX & !3;

/// `io_pread`: exactly `buf.len()` bytes at `pos`.
fn pread(f: &mut File, buf: &mut [u8], pos: u64) -> io::Result<()> {
    f.seek(SeekFrom::Start(pos))?;
    f.read_exact(buf)
}

fn crc32(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

/// `lzma_stream_flags`' check type, from the two flag bytes; `None` when a
/// reserved bit is set.
fn check_of(flags: &[u8]) -> Option<u8> {
    (flags[0] == 0 && flags[1] & 0xf0 == 0).then_some(flags[1] & 0x0f)
}

/// `unxz_len`: the uncompressed size, or 0 when the indexes cannot be read.
pub(super) fn unxz_len(f: &mut File) -> u64 {
    parse_indexes(f).unwrap_or(0)
}

/// `parse_indexes`: the sum of every stream's records.
fn parse_indexes(f: &mut File) -> Option<u64> {
    let size = f.metadata().ok()?.len();
    if size < 2 * HEADER_SIZE {
        return None;
    }
    let mut pos = size;
    let mut total = 0u64;
    loop {
        if pos < 2 * HEADER_SIZE {
            return None;
        }
        pos -= HEADER_SIZE;
        let mut buf = [0u8; HEADER_SIZE as usize];
        // The footer, past any stream padding (multiples of four zeros).
        loop {
            if pos < HEADER_SIZE {
                return None;
            }
            pread(f, &mut buf, pos).ok()?;
            let word =
                |i: usize| u32::from_ne_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap_or([1; 4]));
            if word(2) != 0 {
                break;
            }
            let mut i = 2isize;
            loop {
                pos -= 4;
                i -= 1;
                if i < 0 || word(i as usize) != 0 {
                    break;
                }
            }
        }
        // `lzma_stream_footer_decode`.
        if buf[10..12] != FOOTER_MAGIC
            || crc32(&buf[4..10]) != u32::from_le_bytes(buf[..4].try_into().ok()?)
        {
            return None;
        }
        let footer_check = check_of(&buf[8..10])?;
        let backward_size = (u64::from(u32::from_le_bytes(buf[4..8].try_into().ok()?)) + 1) * 4;
        if pos < backward_size + HEADER_SIZE {
            return None;
        }
        pos -= backward_size;
        let (uncompressed, blocks) = read_index(f, pos, backward_size)?;
        // Back to the stream header.
        pos -= HEADER_SIZE;
        if pos < blocks {
            return None;
        }
        pos -= blocks;
        pread(f, &mut buf, pos).ok()?;
        if buf[..6] != HEADER_MAGIC
            || crc32(&buf[6..8]) != u32::from_le_bytes(buf[8..12].try_into().ok()?)
        {
            return None;
        }
        if check_of(&buf[6..8])? != footer_check {
            return None;
        }
        total = total.checked_add(uncompressed).filter(|&t| t <= VLI_MAX)?;
        if pos == 0 {
            return Some(total);
        }
    }
}

/// The bytes of an index, counted and summed into its CRC32.
struct IndexBytes<'f> {
    src: io::Take<&'f mut File>,
    buf: Vec<u8>,
    at: usize,
    filled: usize,
    crc: flate2::Crc,
    used: u64,
}

impl IndexBytes<'_> {
    fn raw(&mut self) -> Option<u8> {
        if self.at == self.filled {
            self.filled = self.src.read(&mut self.buf).ok()?;
            self.at = 0;
            if self.filled == 0 {
                return None;
            }
        }
        self.at += 1;
        Some(self.buf[self.at - 1])
    }

    fn byte(&mut self) -> Option<u8> {
        let b = self.raw()?;
        self.crc.update(&[b]);
        self.used += 1;
        Some(b)
    }

    /// `lzma_vli_decode`: at most nine bytes, and a final zero byte after
    /// the first (a non-minimal encoding) is an error.
    fn vli(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..9 {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    return None;
                }
                return Some(v);
            }
        }
        None
    }
}

/// An index of `len` bytes at `pos` (`lzma_index_decoder`): the records'
/// uncompressed sizes summed, and the blocks' total size (each unpadded
/// size rounded up to four), checked as liblzma checks them.
fn read_index(f: &mut File, pos: u64, len: u64) -> Option<(u64, u64)> {
    f.seek(SeekFrom::Start(pos)).ok()?;
    let mut r = IndexBytes {
        src: f.take(len),
        buf: vec![0u8; IO_BUFFER_SIZE],
        at: 0,
        filled: 0,
        crc: flate2::Crc::new(),
        used: 0,
    };
    if r.byte()? != 0 {
        return None;
    }
    let records = r.vli()?;
    let (mut uncompressed, mut blocks) = (0u64, 0u64);
    for _ in 0..records {
        let unpadded = r.vli()?;
        let size = r.vli()?;
        if !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&unpadded) || size > VLI_MAX {
            return None;
        }
        blocks = blocks
            .checked_add((unpadded + 3) & !3)
            .filter(|&b| b <= VLI_MAX)?;
        uncompressed = uncompressed.checked_add(size).filter(|&u| u <= VLI_MAX)?;
    }
    while !r.used.is_multiple_of(4) {
        if r.byte()? != 0 {
            return None;
        }
    }
    let want = r.crc.sum();
    let mut stored = [0u8; 4];
    for b in &mut stored {
        *b = r.raw()?;
    }
    // The index must fill exactly what the footer gave it.
    if u32::from_le_bytes(stored) != want || r.used + 4 != len {
        return None;
    }
    Some((uncompressed, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_fields_are_the_calendars() {
        // 2001-09-09 01:46:40 UTC (the harness's input time).
        assert_eq!(utc_fields(1_000_000_000), (8, 9, 1, 46));
        assert_eq!(utc_fields(0), (0, 1, 0, 0));
        assert_eq!(utc_fields(1_234_567_890), (1, 13, 23, 31));
    }

    #[test]
    fn ctime_short_pads_the_day() {
        let s = ctime_short(1_000_000_000);
        assert_eq!(s.len(), 12, "{s}");
        assert_eq!(&s[3..4], " ");
    }
}
