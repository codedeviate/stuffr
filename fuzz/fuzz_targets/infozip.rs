//! Info-ZIP UnZip 6.0's own decoders (`stuffr::infozip`, 0.16.0 Task 15):
//! `inflate` (deflate and deflate64), `explode`, `unshrink` and `crypt`'s
//! `test_key` + decryption, fed raw streams.
//!
//! An input is `[selector] ++ rest`; `selector % 6` picks the run:
//!
//! - 0, 1: `rest` through `inflate`, plain deflate (0) or deflate64 (1);
//! - 2: `explode`, `rest` = `[flags][ucsize; 3, LE] ++ stream` (`flags`
//!   is the general-purpose flag's low byte: bit 1 the 8 KiB window, bit 2
//!   the literal tree);
//! - 3: `rest` through `unshrink`;
//! - 4, 5: `rest` = `[n][password; n % 17][check][header; 12] ++ data`:
//!   `test_key(password, header, check)`, and on a match `data` decrypted
//!   and inflated (deflate64 when `(selector / 6) & 1`). 4 decrypts `data`
//!   first and inflates it from a slice, as unzip does; 5 decrypts while
//!   inflating, through funzip's `NEXTBYTE` (`FunzipSource`), whose EOF is
//!   not sticky.
//!
//! Every run gets a fresh zeroed window (`WSIZE`, unzip's `slide[]` as a new
//! `G` has it) and a flush callback that refuses past 8 MiB of output
//! (`OUTPUT_CAP`, the sandbox's budget).
//!
//! Asserted, for every input:
//!
//! - no panic, and the decoder returns (a hang is libFuzzer's timeout);
//! - a refused flush comes back as `Stop::Flush`, unchanged, and only a
//!   refused flush does;
//! - inflate prints at most one message (`(incomplete l-tree)  ` or
//!   `(incomplete d-tree)  `), and only just before its `Stop::Code(1)`;
//! - a linear-work bound: the output is at most `RATIO × bytes read +
//!   SLACK`, with `RATIO` the format's own maximum expansion (see
//!   `INFLATE_RATIO`, `INFLATE64_RATIO` and `UNSHRINK_RATIO` for each
//!   figure and where it comes from); explode is held to its `ucsize`
//!   instead (`EXPLODE_OVERSHOOT`): at its EOF it reads one bits for ever,
//!   so its input does not bound it, the size does;
//! - `test_key` agrees with an independent `Keys::new` + `decrypt` of the
//!   header, and the keys it returns decrypt `data` as those do.

#![no_main]

use libfuzzer_sys::fuzz_target;
use stuffr::infozip::crypt::{self, Keys, RAND_HEAD_LEN};
use stuffr::infozip::{ByteSource, Stop, WSIZE, explode, inflate, unshrink};

/// The flush callback refuses output past this: the sandbox's 8 MiB budget
/// (`SANDBOX_OUTPUT_CAP`), the bound unzip's own output has under fuzzing.
const OUTPUT_CAP: u64 = 8 * 1024 * 1024;

/// Plain deflate's maximum expansion, bytes out per byte in: a dynamic
/// block whose literal/length tree holds only end-of-block and code 285
/// (length 258), one bit each, and whose distance tree is one 1-bit code,
/// sends 258 bytes per 2 bits, 1032 per byte, and nothing sends more (285
/// has no extra bits and every code is at least one bit). Measured with the
/// `inflate-bomb` seed (`fuzz_corpus.rs`'s `deflate_bomb`, 16,384 such
/// matches): 4,227,072 bytes from 4,110 = 1,028.5 per byte (the block header
/// is the gap; `the_infozip_seeds_carry_their_shape` pins the size).
const INFLATE_RATIO: u64 = 1032;

/// Deflate64's: code 285 is length 3 plus 16 extra bits, so 65,538 bytes per
/// 1 + 16 + 1 = 18 bits, 29,128 per byte (rounded up). Measured with the
/// `inflate64-bomb` seed (100 such matches): 6,553,800 bytes from 239 =
/// 27,421.8 per byte.
const INFLATE64_RATIO: u64 = 29_128;

/// unshrink's: every code that is not an escape is at least 9 bits and
/// writes at most the 8 KiB stack (`HSIZE`, `Stack[]`; a longer string is
/// its "buffer underflow" `PK_ERR`), so 8192 bytes per 9 bits, 7282 per
/// byte (rounded up). A real stream stays well under it: a chain of
/// KwKwK codes, each one byte longer than the last, is the longest output a
/// table can build. Measured with the `unshrink-chain` seed (3,800 such
/// codes, 9 to 12 bits): 7,225,701 bytes from 5,357 = 1,348.8 per byte;
/// carried on to a full table (7,935 codes, 13 bits from code 4096) the
/// same chain is 31,494,016 bytes from 12,075 = 2,608.2 per byte (computed),
/// which the 8 MiB cap never lets a run see; a full table refuses the next
/// code (`PK_ERR`), and a partial clear to go on costs 26 bits more per
/// code.
const UNSHRINK_RATIO: u64 = 7282;

/// What a stream may add to `RATIO × bytes read`: inflate decodes one
/// symbol more from the zero bits past EOF (its "read beyond EOF"
/// tolerance), at most a deflate64 match (65,538 bytes), and the decoders
/// write in 64 KiB windows; two windows cover both.
const SLACK: u64 = 2 * WSIZE as u64;

/// How far explode may write past `ucsize`: its last match is copied
/// whole whatever `s` has left (`explode.c`: `s = (s > n ? s - n : 0)`,
/// then the copy of `n`), and the longest match is 66 + 255 = 321 bytes
/// (`cplen3`'s last base plus 8 extra bits), so at most 320 past it.
const EXPLODE_OVERSHOOT: u64 = 320;

/// At most this many reads past funzip's end of input in `FunzipSource`:
/// its `NEXTBYTE` gives a value there as long as the key byte is not 0,
/// and inflate decodes on in those bits (Task 12's probes: MBs of output
/// from a stream cut short, on both references). The 8 MiB cap stops a run
/// that writes; this stops one that would read without writing (empty
/// blocks for ever), with the EOF funzip itself gives when the key byte is
/// 0. 2^20 reads past the end is a few milliseconds instrumented.
const FUNZIP_EOF_READS: u64 = 1 << 20;

/// The flush callback's error: the output cap was reached.
#[derive(Debug, PartialEq, Eq)]
struct Capped;

/// Output so far, and whether the cap refused a flush.
#[derive(Default)]
struct Out {
    total: u64,
    refused: bool,
}

impl Out {
    fn flush(&mut self, chunk: &[u8]) -> Result<(), Capped> {
        assert!(
            !self.refused,
            "infozip: flushed again after a refused flush"
        );
        let n = chunk.len() as u64;
        if self.total + n > OUTPUT_CAP {
            self.refused = true;
            return Err(Capped);
        }
        self.total += n;
        Ok(())
    }
}

/// A refused flush came back as `Stop::Flush(Capped)`, and nothing else
/// did.
fn check_stop(what: &str, out: &Out, r: &Result<(), Stop<Capped>>) {
    match r {
        Err(Stop::Flush(Capped)) => assert!(out.refused, "{what}: Stop::Flush without a refusal"),
        _ => assert!(
            !out.refused,
            "{what}: the flush was refused, but it returned {r:?}"
        ),
    }
}

/// The linear-work bound: at most `ratio` bytes out per byte read, plus
/// `SLACK`.
fn check_ratio(what: &str, out: &Out, read: u64, ratio: u64) {
    assert!(
        out.total <= ratio * read + SLACK,
        "infozip: {what} wrote {} bytes from {read} read, past {ratio} per byte + {SLACK}",
        out.total
    );
}

/// `inflate` over `src`, checked; `read` gives the bytes it read.
fn run_inflate<S: ByteSource>(src: &mut S, deflate64: bool, read: impl Fn(&S) -> u64) {
    let mut window = vec![0u8; WSIZE];
    let mut out = Out::default();
    let mut messages: Vec<&'static str> = Vec::new();
    let r = inflate(
        src,
        deflate64,
        &mut window,
        &mut |c| out.flush(c),
        &mut |m| messages.push(m),
    );
    let what = if deflate64 { "inflate64" } else { "inflate" };
    check_stop(what, &out, &r);
    assert!(
        messages.is_empty() || (messages.len() == 1 && matches!(r, Err(Stop::Code(1)))),
        "infozip: {what} printed {messages:?} and returned {r:?}"
    );
    let ratio = if deflate64 {
        INFLATE64_RATIO
    } else {
        INFLATE_RATIO
    };
    check_ratio(what, &out, read(src), ratio);
}

/// `inflate` over a slice (unzip's `NEXTBYTE`: a sticky EOF).
fn inflate_slice(data: &[u8], deflate64: bool) {
    let mut src = data.iter();
    let len = data.len() as u64;
    run_inflate(&mut src, deflate64, |s| len - s.len() as u64);
}

/// funzip's `NEXTBYTE` for an encrypted entry (crypt.h under `FUNZIP`):
/// `update_keys(getc(in) ^ decrypt_byte())`. At the end of the input
/// `getc` is `EOF`, and the value is `EOF ^ (decrypted byte ^ 0xff)`, an
/// `EOF` only when that is 0: otherwise a negative `int` that
/// `next_bits` sign-extends, so the source gives values again after its
/// end, as `compat::unzip::funzip`'s `Src` does. Past `FUNZIP_EOF_READS` of
/// them it answers `EOF` for good.
struct FunzipSource<'a> {
    data: std::slice::Iter<'a, u8>,
    keys: Keys,
    /// Values given past the end.
    past_end: u64,
}

impl FunzipSource<'_> {
    /// `NEXTBYTE` as the C `int`.
    fn nextbyte(&mut self) -> i32 {
        match self.data.next() {
            Some(&c) => i32::from(self.keys.decrypt_byte(c)),
            None if self.past_end >= FUNZIP_EOF_READS => -1,
            None => {
                self.past_end += 1;
                let low = self.keys.decrypt_byte(0xff);
                -1 ^ i32::from(low ^ 0xff)
            }
        }
    }
}

impl ByteSource for FunzipSource<'_> {
    fn next_byte(&mut self) -> Option<u8> {
        self.next_bits().map(|c| c as u8)
    }

    fn next_bits(&mut self) -> Option<u64> {
        match self.nextbyte() {
            -1 => None,
            c => Some(i64::from(c) as u64),
        }
    }

    fn remaining(&self) -> u64 {
        0
    }
}

/// `explode` with `flags` and `ucsize`, checked.
fn run_explode(flags: u16, ucsize: u64, data: &[u8]) {
    let mut window = vec![0u8; WSIZE];
    let mut out = Out::default();
    let mut src = data.iter();
    let r = explode(&mut src, flags, ucsize, &mut window, &mut |c| out.flush(c));
    check_stop("explode", &out, &r);
    assert!(
        out.total <= ucsize + EXPLODE_OVERSHOOT,
        "infozip: explode wrote {} bytes for a ucsize of {ucsize}",
        out.total
    );
    if matches!(r, Ok(()) | Err(Stop::Length { .. })) {
        assert!(
            out.total >= ucsize,
            "infozip: explode returned {r:?} after {} bytes of a ucsize of {ucsize}",
            out.total
        );
    }
    if let Err(Stop::Length { unused }) = r {
        assert!(unused != 0, "infozip: explode's Length with unused 0");
    }
}

/// `unshrink`, checked.
fn run_unshrink(data: &[u8]) {
    let mut window = vec![0u8; WSIZE];
    let mut out = Out::default();
    let mut src = data.iter();
    let r = unshrink(&mut src, &mut window, &mut |c| out.flush(c));
    check_stop("unshrink", &out, &r);
    check_ratio("unshrink", &out, data.len() as u64, UNSHRINK_RATIO);
}

/// `test_key`, checked against an independent decryption of the header,
/// then the data decrypted and inflated, as unzip (`funzip == false`) or
/// funzip does it.
fn run_crypt(rest: &[u8], deflate64: bool, funzip: bool) {
    let Some((&n, rest)) = rest.split_first() else {
        return;
    };
    let n = usize::from(n % 17);
    if rest.len() < n + 1 + RAND_HEAD_LEN {
        return;
    }
    let (password, rest) = rest.split_at(n);
    let (&check, rest) = rest.split_first().expect("length checked");
    let (header, data) = rest.split_at(RAND_HEAD_LEN);
    let header: &[u8; RAND_HEAD_LEN] = header.try_into().expect("split at RAND_HEAD_LEN");

    let mut independent = Keys::new(password);
    let mut plain = *header;
    independent.decrypt(&mut plain);
    let keys = crypt::test_key(password, header, check);
    assert_eq!(
        keys.is_some(),
        plain[RAND_HEAD_LEN - 1] == check,
        "infozip: test_key disagrees with the header's own decryption"
    );
    let Some(keys) = keys else {
        return;
    };
    let mut ours = data.to_vec();
    keys.clone().decrypt(&mut ours);
    let mut theirs = data.to_vec();
    independent.decrypt(&mut theirs);
    assert!(
        ours == theirs,
        "infozip: test_key's keys decrypt differently"
    );
    if funzip {
        let mut src = FunzipSource {
            data: data.iter(),
            keys,
            past_end: 0,
        };
        let len = data.len() as u64;
        run_inflate(&mut src, deflate64, |s| {
            len - s.data.len() as u64 + s.past_end
        });
    } else {
        inflate_slice(&ours, deflate64);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let wide = (selector / 6) & 1 == 1;
    match selector % 6 {
        0 => inflate_slice(rest, false),
        1 => inflate_slice(rest, true),
        2 => {
            if rest.len() < 4 {
                return;
            }
            let flags = u16::from(rest[0]);
            let ucsize = u64::from(u32::from_le_bytes([rest[1], rest[2], rest[3], 0]));
            run_explode(flags, ucsize, &rest[4..]);
        }
        3 => run_unshrink(rest),
        4 => run_crypt(rest, wide, false),
        _ => run_crypt(rest, wide, true),
    }
});
