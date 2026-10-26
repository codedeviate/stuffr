use super::*;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Mutex;

use crate::compat::host::{InputReads, Sandbox};
use crate::compat::zip::Flavour;

/// A scratch directory, removed on drop (`stuffr-zipup-<pid>-<tag>-<n>`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("stuffr-zipup-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `zip args` in a sandbox over `dir`, the input `name` given `reads`'
/// test limits: (exit, stdout, stderr).
fn run(dir: &Path, args: &[&str], name: &str, reads: InputReads) -> (i32, String, String) {
    let log = Arc::new(Mutex::new(BTreeMap::new()));
    log.lock().unwrap().insert(dir.join(name), reads);
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(Vec::new()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(u64::MAX)),
        reads: log,
    });
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let env = |_: &str| None;
    let mut err = Vec::new();
    let code = crate::compat::zip::main(Flavour::Apple, "zip", b"zip", &args, &env, host, &mut err);
    let out = stdout.lock().unwrap().clone();
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// The first local header's method, CRC, compressed and uncompressed size,
/// and the central header's.
fn sizes(zip: &[u8]) -> ([u32; 4], [u32; 4]) {
    let le16 = |b: &[u8], at: usize| u32::from(u16::from_le_bytes([b[at], b[at + 1]]));
    let le32 = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    assert_eq!(&zip[..4], b"PK\x03\x04");
    let local = [le16(zip, 8), le32(zip, 14), le32(zip, 18), le32(zip, 22)];
    let c = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    let central = [
        le16(zip, c + 10),
        le32(zip, c + 16),
        le32(zip, c + 20),
        le32(zip, c + 24),
    ];
    (local, central)
}

fn crc(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

/// Text that deflates (base64-like lines).
fn big(n: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push(b"ABCDEFGHabcdefgh0123+/"[(x >> 40) as usize % 22]);
        if v.len() % 77 == 76 {
            v.push(b'\n');
        }
    }
    v.truncate(n);
    v
}

/// Review Focus 1, the shrink: the file ends early while zip reads it
/// (the test's `eof_after`). The record's answer (`race.pl`, both
/// references): the size-changed warning inside the `adding:` line, exit 0,
/// and an entry of the bytes actually read, its sizes and CRC theirs.
#[test]
fn a_file_that_changes_while_zipping_warns_as_zip_does() {
    let data = big(3_000_000);
    for (level, method, tail) in [("-0", 0, " (stored 0%)\n"), ("-6", 8, "")] {
        let s = Scratch::new("shrink");
        std::fs::write(s.0.join("big"), &data).unwrap();
        let cut = 1_000_000u64;
        let reads = InputReads {
            eof_after: Some(cut),
            ..Default::default()
        };
        let (code, out, err) = run(&s.0, &[level, "t.zip", "big"], "big", reads);
        assert_eq!((code, err.as_str()), (0, ""), "{level} {out}");
        let want = "  adding: big\n\tzip warning:  file size changed while zipping big\n";
        assert!(out.starts_with(want), "{level}: {out:?}");
        if method == 0 {
            assert_eq!(&out[want.len()..], tail);
        } else {
            assert!(out[want.len()..].starts_with(" (deflated "), "{out:?}");
        }
        let zip = std::fs::read(s.0.join("t.zip")).unwrap();
        let (local, central) = sizes(&zip);
        let read = &data[..cut as usize];
        assert_eq!(local[0], method);
        assert_eq!(local[1], crc(read), "{level}");
        assert_eq!(local[3], cut as u32, "{level}");
        assert_eq!(local, central, "{level}");
        if method == 0 {
            assert_eq!(local[2], cut as u32);
        }
    }

    // The grow: the file is longer than `stat` said when zip reads it (bytes
    // appended once it is open). The same warning; the entry holds every
    // byte up to the new end.
    for (level, method) in [("-0", 0), ("-6", 8)] {
        let s = Scratch::new("grow");
        std::fs::write(s.0.join("big"), &data[..2_000_000]).unwrap();
        AFTER_OPEN.with(|h| {
            *h.borrow_mut() = Some(Box::new(|p: &Path| {
                let mut f = File::options().append(true).open(p).unwrap();
                f.write_all(&big(3_000_000)[2_000_000..]).unwrap();
            }));
        });
        let (code, out, err) = run(&s.0, &[level, "t.zip", "big"], "big", InputReads::default());
        AFTER_OPEN.with(|h| *h.borrow_mut() = None);
        assert_eq!((code, err.as_str()), (0, ""), "{level} {out}");
        assert!(
            out.starts_with("  adding: big\n\tzip warning:  file size changed while zipping big\n"),
            "{level}: {out:?}"
        );
        let zip = std::fs::read(s.0.join("t.zip")).unwrap();
        let (local, central) = sizes(&zip);
        assert_eq!(local[0], method);
        assert_eq!(local[1], crc(&data));
        assert_eq!(local[3], data.len() as u32);
        assert_eq!(local, central);
    }
}

/// Ruling Z9: a read error is the end of the input, as zipup's
/// `file_read` takes it. A stored entry then also says why (`perror` on
/// standard error) and that the file could not be read; a deflated one does
/// not (zipup's `zerr()` looks at the stored loop's count only). Both warn
/// that the size changed, and the entry holds what was read.
#[test]
fn a_read_error_is_the_end_of_the_input() {
    let data = big(200_000);
    for (level, stored) in [("-0", true), ("-6", false)] {
        let s = Scratch::new("eio");
        std::fs::write(s.0.join("big"), &data).unwrap();
        let reads = InputReads {
            fail_after: Some(50_000),
            ..Default::default()
        };
        let (code, out, err) = run(&s.0, &[level, "t.zip", "big"], "big", reads);
        assert_eq!(code, 0, "{out} {err}");
        let changed = "\tzip warning:  file size changed while zipping big\n";
        if stored {
            assert_eq!(err, "\nzip warning: Input/output error\n");
            assert_eq!(
                out,
                format!(
                    "  adding: big\n\tzip warning: could not read input file: big\n{changed} (stored 0%)\n"
                )
            );
        } else {
            assert_eq!(err, "");
            assert!(
                out.starts_with(&format!("  adding: big\n{changed}")),
                "{out:?}"
            );
        }
        let zip = std::fs::read(s.0.join("t.zip")).unwrap();
        let (local, _) = sizes(&zip);
        assert_eq!(local[3], 50_000);
        assert_eq!(local[1], crc(&data[..50_000]));
    }
}

/// Task 2 review (c): `ZipDeflater::new` takes levels 1 to 9 only; `-0`
/// before `-Z deflate` reaches deflate with level 0, which zip answers
/// with `lm_init`'s "bad pack level" (`ZE_LOGIC`), never a panic.
#[test]
fn level_0_deflate_is_zips_logic_error() {
    let s = Scratch::new("lvl0");
    std::fs::write(s.0.join("b.txt"), big(5000)).unwrap();
    let (code, out, _) = run(
        &s.0,
        &["-0", "-Z", "deflate", "t.zip", "b.txt"],
        "b.txt",
        InputReads::default(),
    );
    assert_eq!(
        (code, out.as_str()),
        (
            5,
            "  adding: b.txt\n\nzip error: Internal logic error (bad pack level)\n"
        )
    );
    assert!(!s.0.join("t.zip").exists());
    assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 1, "temp left");
}

/// The sandbox's input accounting sees every input: one open per file,
/// its bytes read once.
#[test]
fn inputs_are_opened_through_track() {
    let s = Scratch::new("track");
    std::fs::write(s.0.join("big"), big(100_000)).unwrap();
    let log = Arc::new(Mutex::new(BTreeMap::new()));
    let host = Host::Sandbox(Sandbox {
        dir: s.0.clone(),
        stdin: Some(Vec::new()),
        stdout: Arc::new(Mutex::new(Vec::new())),
        budget: Arc::new(AtomicU64::new(u64::MAX)),
        reads: log.clone(),
    });
    let args = vec![OsString::from("t.zip"), OsString::from("big")];
    let env = |_: &str| None;
    let mut err = Vec::new();
    let code = crate::compat::zip::main(Flavour::Apple, "zip", b"zip", &args, &env, host, &mut err);
    assert_eq!(code, 0);
    let r = log.lock().unwrap()[&s.0.join("big")];
    assert_eq!((r.opens, r.bytes, r.len), (1, 100_000, 100_000));
}

#[test]
fn percent_is_zips() {
    assert_eq!(percent(6, 8), -32);
    assert_eq!(percent(2240, 170), 92);
    assert_eq!(percent(0, 5), 0);
    assert_eq!(percent(4, 6), -49);
    assert_eq!(percent(100, 100), 0);
}

#[test]
fn write_num_string_is_zips() {
    for (n, s) in [
        (0, "0"),
        (6, "6"),
        (999, "999"),
        (1000, "0.9K"),
        (2240, "2.1K"),
        (10239, "9.9K"),
        (10240, "10K"),
        (1 << 20, "1.0M"),
        (u64::MAX, "15?"),
    ] {
        assert_eq!(write_num_string(n), s, "{n}");
    }
}

#[test]
fn suffixes_match_from_the_end() {
    let s = b".Z:.zip:.zoo:.arc:.lzh:.arj";
    assert!(suffixes(b"x.Z", s));
    assert!(suffixes(b"d/x.zip", s));
    assert!(!suffixes(b"x.z", s));
    assert!(!suffixes(b"Z", s));
    assert!(suffixes(b"a.txt", b".txt"));
    assert!(suffixes(b"anything", b""));
}

/// `-l` and `-ll` per request, as `file_read` does them.
#[test]
fn file_read_translates_each_request() {
    let mut src: &[u8] = b"a\nb\n";
    let mut r = FileRead {
        src: &mut src,
        translate_eol: 1,
        file_binary: -1,
        err: None,
        scratch: Vec::new(),
    };
    let mut buf = [0u8; 8];
    // half the room is read: four bytes, two LFs
    assert_eq!(r.file_read(&mut buf), 6);
    assert_eq!(&buf[..6], b"a\r\nb\r\n");
    let mut src: &[u8] = b"a\r\nb\r";
    let mut r = FileRead {
        src: &mut src,
        translate_eol: 2,
        file_binary: -1,
        err: None,
        scratch: Vec::new(),
    };
    let mut buf = [0u8; 64];
    // the CR at the end of the read is dropped as half of a CR LF
    let n = r.file_read(&mut buf);
    assert_eq!(&buf[..n], b"a\nb");
    // binary data is left alone
    let mut src: &[u8] = b"\x00\n\x01";
    let mut r = FileRead {
        src: &mut src,
        translate_eol: 1,
        file_binary: -1,
        err: None,
        scratch: Vec::new(),
    };
    let mut buf = [0u8; 64];
    let n = r.file_read(&mut buf);
    assert_eq!(&buf[..n], b"\x00\n\x01");
    assert_eq!(r.file_binary, 1);
}
