//! zipinfo.c's pieces, unit by unit, and sandboxed runs over hostile
//! directories. The differentials against the reference are in
//! `tests/compat_unzip_apple.rs` (`zipinfo_*`) and the shared rows.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::short::{Attribs, unix_letters, version};
use super::*;
use crate::compat::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox};
use crate::compat::unzip::{EXIT_CODES_APPLE, EXIT_CODES_UBUNTU, Flavour, run_in_counted};

/// A run's `G` in a sandbox (UTC), for the pieces that read `uO`.
fn with_uz<R>(f: impl FnOnce(&mut Uz) -> R) -> R {
    let env = |_: &str| None;
    let mut err = Vec::new();
    let host = Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: None,
        stdout: Arc::new(Mutex::new(Vec::new())),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: Arc::new(Mutex::new(BTreeMap::new())),
    });
    let mut uz = Uz::new(host, Flavour::Apple, &env, &mut err);
    f(&mut uz)
}

/// 2020-01-02 03:04:06 as an MS-DOS date and time.
const DOS_2020: u32 = ((((2020 - 1980) << 9) | (1 << 5) | 2) << 16) | (3 << 11) | (4 << 5) | 3;

/// zi_time()'s three formats, from the MS-DOS fields and from a Unix time
/// (probe: `zipinfo -s`, `-T`, `-v` of entries with and without `UT`).
#[test]
fn times_in_each_format() {
    with_uz(|uz| {
        uz.o.lflag = 3;
        assert_eq!(
            zi_time(uz, DOS_2020, None, Clock::Local),
            b"20-Jan-02 03:04"
        );
        uz.o.t_flag = true;
        assert_eq!(
            zi_time(uz, DOS_2020, None, Clock::Local),
            b"20200102.030406"
        );
        uz.o.lflag = 10;
        assert_eq!(
            zi_time(uz, DOS_2020, None, Clock::Local),
            b"2020 Jan 2 03:04:06"
        );
        // A Unix time, local (UTC in a sandbox) and UTC.
        assert_eq!(
            zi_time(uz, 0, Some(1_600_000_000), Clock::Local),
            b"2020 Sep 13 12:26:40"
        );
        assert_eq!(
            zi_time(uz, 0, Some(1_600_000_000), Clock::Utc),
            b"2020 Sep 13 12:26:40"
        );
        // Before 1970, and past 2038 (`date -u -r`).
        assert_eq!(
            zi_time(uz, 0, Some(-1_879_048_192), Clock::Utc),
            b"1910 Jun 16 18:10:08"
        );
        assert_eq!(
            zi_time(uz, 0, Some(0x9000_0000), Clock::Utc),
            b"2046 Jul 23 00:38:24"
        );
    });
}

/// A month outside 1..12 shows as `%03d`; the DOS fields print as stored
/// (hours to 31, minutes to 63, seconds to 62).
#[test]
fn bogus_months_and_fields_print_as_numbers() {
    with_uz(|uz| {
        uz.o.lflag = 3;
        let t = (40 << 25) | (13 << 21) | (1 << 16);
        assert_eq!(zi_time(uz, t, None, Clock::Local), b"20-013-01 00:00");
        assert_eq!(zi_time(uz, 0, None, Clock::Local), b"80-000-00 00:00");
        uz.o.lflag = 10;
        assert_eq!(
            zi_time(uz, 0xffff_ffff, None, Clock::Local),
            b"2107 015 31 31:63:62"
        );
        uz.o.lflag = 3;
        uz.o.t_flag = true;
        assert_eq!(
            zi_time(uz, 0xffff_ffff, None, Clock::Local),
            b"21071531.316362"
        );
    });
}

/// ruling: `attribs[16]` grows for a version of 10.0 or more after
/// offset 12 instead of being overrun.
#[test]
fn attribs_grow_instead_of_overflowing() {
    let mut a = Attribs::new(15, b' ');
    let pad = |n: usize, tail: &str| [" ".repeat(n), tail.to_owned()].concat().into_bytes();
    assert_eq!(a.text(), pad(15, ""));
    a.sprintf_at(12, &version(255));
    assert_eq!(a.text(), pad(12, "25.5"));
    a.sprintf_at(12, &version(30));
    assert_eq!(a.text(), pad(12, "3.0"));
    let mut a = Attribs::new(0, 0);
    a.set(20, b'x');
    assert_eq!(a.text(), b"");
}

/// The Unix letters, both set-group-id spellings.
#[test]
fn unix_letters_spell_the_mode() {
    let spell = |mode: u32, sgid: u8| {
        let mut a = Attribs::new(10, b' ');
        unix_letters(&mut a, mode, sgid);
        String::from_utf8(a.text().to_vec()).unwrap()
    };
    assert_eq!(spell(0o100644, b'S'), "-rw-r--r--");
    assert_eq!(spell(0o040755, b'S'), "drwxr-xr-x");
    assert_eq!(spell(0o120777, b'l'), "lrwxrwxrwx");
    assert_eq!(spell(0o107000, b'S'), "---S--S--T");
    assert_eq!(spell(0o107000, b'l'), "---S--l--T");
    assert_eq!(spell(0o107111, b'S'), "---s--s--t");
    assert_eq!(spell(0o000000, b'S'), "?---------");
    for (t, c) in [
        (0o060000, 'b'),
        (0o020000, 'c'),
        (0o010000, 'p'),
        (0o140000, 's'),
    ] {
        assert!(spell(t, b'S').starts_with(c));
    }
}

/// The `%llu`/`%.16llX` helpers the reports use.
#[test]
fn offsets_print_in_decimal_and_sixteen_hex_digits() {
    assert_eq!(zu(0), b"0");
    assert_eq!(zu_w(12, 8), [&[b' '; 6][..], b"12"].concat());
    assert_eq!(zu_w(123_456_789_012, 8), b"123456789012");
    assert_eq!(zx(594), b"0000000000000252");
    assert_eq!(zx(u64::MAX), b"FFFFFFFFFFFFFFFF");
}

/// One central header (made on Unix, version 3.0) with `extra` and the
/// given lengths, then the end record counting `count` entries.
fn central_archive(headers: &[Vec<u8>], count: u16) -> Vec<u8> {
    let cd: Vec<u8> = headers.concat();
    let mut v = vec![0u8; 16];
    v.extend_from_slice(&cd);
    v.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&[0, 0]);
    v
}

fn header(made_by: u16, method: u16, attr: u32, name: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut h = b"PK\x01\x02".to_vec();
    for w in [made_by, 20, 0, method] {
        h.extend_from_slice(&w.to_le_bytes());
    }
    h.extend_from_slice(&DOS_2020.to_le_bytes());
    h.extend_from_slice(&[0; 12]);
    for w in [name.len() as u16, extra.len() as u16, 0, 0, 0] {
        h.extend_from_slice(&w.to_le_bytes());
    }
    h.extend_from_slice(&attr.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(name);
    h.extend_from_slice(extra);
    h
}

/// A tiny xorshift, so the damage below is the same every run.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Every format over archives damaged at random (headers whose hosts,
/// versions, methods and attributes are random, extra fields of random
/// blocks, lengths that run past the end) never panics and answers one of
/// the flavour's exit codes; nothing it allocates is sized by the input
/// beyond a field's width.
#[test]
fn hostile_directories_never_panic() {
    let dir = std::env::temp_dir().join(format!("stuffr-zipinfo-hostile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ids: [u16; 24] = [
        0x0001, 0x0009, 0x4c41, 0x4453, 0x4d49, 0x5855, 0x7855, 0x7875, 0x5455, 0x7075, 0x6375,
        0x334d, 0x07c8, 0x2605, 0x2705, 0x4d63, 0x6542, 0x7441, 0xfb4a, 0x5356, 0x4154, 0x4b46,
        0x1234, 0xffff,
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let formats: [&[&str]; 8] = [
        &["-1"],
        &["-2t"],
        &["-s"],
        &["-m"],
        &["-l"],
        &["-v"],
        &["-vT"],
        &["-hzt"],
    ];
    for round in 0..120 {
        let mut headers = Vec::new();
        for i in 0..1 + rng.next() % 4 {
            let mut extra = Vec::new();
            for _ in 0..rng.next() % 4 {
                let id = ids[(rng.next() % ids.len() as u64) as usize];
                let len = (rng.next() % 72) as usize;
                let claim = if rng.next().is_multiple_of(5) {
                    (len + 1 + (rng.next() % 40) as usize) as u16
                } else {
                    len as u16
                };
                extra.extend_from_slice(&id.to_le_bytes());
                extra.extend_from_slice(&claim.to_le_bytes());
                extra.extend((0..len).map(|_| rng.next() as u8));
            }
            let made_by = rng.next() as u16;
            let method = if rng.next().is_multiple_of(3) {
                rng.next() as u16
            } else {
                (rng.next() % 20) as u16
            };
            let mut h = header(
                made_by,
                method,
                rng.next() as u32,
                format!("e{i}").as_bytes(),
                &extra,
            );
            // flags, sizes, internal attributes: random
            h[8] = rng.next() as u8;
            for b in &mut h[20..28] {
                *b = rng.next() as u8;
            }
            h[36] = rng.next() as u8;
            headers.push(h);
        }
        let mut z = central_archive(&headers, headers.len() as u16);
        if round % 3 == 0 {
            // a length that runs into the end record
            let at = 16 + 28 + (rng.next() % 3) as usize * 2;
            z[at] = 0xff;
        }
        std::fs::write(dir.join("h.zip"), &z).unwrap();
        for f in [Flavour::Apple, Flavour::Ubuntu] {
            let codes = match f {
                Flavour::Apple => EXIT_CODES_APPLE,
                Flavour::Ubuntu => EXIT_CODES_UBUNTU,
            };
            for args in formats {
                let mut a: Vec<OsString> = args.iter().map(OsString::from).collect();
                a.push("h.zip".into());
                let (code, ..) = run_in_counted(f, &dir, "zipinfo", &a, b"", &|_| None);
                assert!(codes.contains(&code), "round {round} {args:?}: exit {code}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A host number between 20 and 29 is `(null)` in `-v` (the C passes
/// `NULL` to `%s`; probe: `zipinfo -v` of an entry made by host 20), and
/// `???` in `-s`.
#[test]
fn unnamed_hosts() {
    let dir = std::env::temp_dir().join(format!("stuffr-zipinfo-hosts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let z = central_archive(&[header(0x141e, 0, 0o100644 << 16, b"h", b"")], 1);
    std::fs::write(dir.join("h.zip"), z).unwrap();
    let run = |args: &[&str]| {
        let mut a: Vec<OsString> = args.iter().map(OsString::from).collect();
        a.push("h.zip".into());
        let (code, out, err, _) =
            run_in_counted(Flavour::Apple, &dir, "zipinfo", &a, b"", &|_| None);
        assert_eq!((code, err.as_slice()), (0, &b""[..]));
        String::from_utf8(out).unwrap()
    };
    let v = run(&["-v"]);
    assert!(
        v.lines().any(
            |l| l.starts_with("  file system or operating system of origin: ")
                && l.ends_with(" (null)")
        ),
        "{v}"
    );
    let s = run(&["-s"]);
    let line = s.lines().nth(2).unwrap_or_default();
    let words: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        words[..6],
        ["-rw-r--r--", "3.0", "???", "0", "b-", "stor"],
        "{s}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
