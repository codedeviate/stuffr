//! The extraction's own pieces, and hostile archives through the sandbox
//! (R7): whatever an archive holds, a run never panics, exits with one of
//! the flavour's codes, and writes nothing outside its directory.

use super::*;
use crate::compat::unzip::{EXIT_CODES_APPLE, EXIT_CODES_UBUNTU, Flavour, run_in_counted};
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// A scratch directory removed on drop, with `root/` (the run's) and
/// `outside/` beside it.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("stuffr-unzip-x-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("root")).unwrap();
        std::fs::create_dir_all(p.join("outside")).unwrap();
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // a hostile run can leave directories without write permission
        fn open_up(p: &Path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = std::fs::symlink_metadata(p)
                    && md.is_dir()
                {
                    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
                    if let Ok(rd) = std::fs::read_dir(p) {
                        for e in rd.flatten() {
                            open_up(&e.path());
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            let _ = p;
        }
        open_up(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One entry of [`zip`]: name, data as stored, method, flags, external
/// attributes, made-by host.
struct E<'a> {
    name: &'a [u8],
    data: Vec<u8>,
    plain_crc: u32,
    ucsize: u32,
    method: u16,
    flags: u16,
    attr: u32,
    host: u8,
}

fn crc(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

fn stored<'a>(name: &'a [u8], data: &[u8], attr: u32) -> E<'a> {
    E {
        name,
        data: data.to_vec(),
        plain_crc: crc(data),
        ucsize: data.len() as u32,
        method: 0,
        flags: 0,
        attr,
        host: 3,
    }
}

fn deflated<'a>(name: &'a [u8], data: &[u8]) -> E<'a> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    E {
        data: enc.finish().unwrap(),
        method: 8,
        ..stored(name, data, 0o100644 << 16)
    }
}

/// A zip archive of `entries` (no Zip64), local headers then the central
/// directory and the end record.
fn zip(entries: &[E]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for e in entries {
        let off = out.len() as u32;
        let mut h = b"PK\x03\x04".to_vec();
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(&e.flags.to_le_bytes());
        h.extend_from_slice(&e.method.to_le_bytes());
        h.extend_from_slice(&0x5021_0000u32.to_le_bytes());
        h.extend_from_slice(&e.plain_crc.to_le_bytes());
        h.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        h.extend_from_slice(&e.ucsize.to_le_bytes());
        h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(e.name);
        out.extend_from_slice(&h);
        out.extend_from_slice(&e.data);
        let mut c = b"PK\x01\x02".to_vec();
        c.extend_from_slice(&[30, e.host]);
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&e.flags.to_le_bytes());
        c.extend_from_slice(&e.method.to_le_bytes());
        c.extend_from_slice(&0x5021_0000u32.to_le_bytes());
        c.extend_from_slice(&e.plain_crc.to_le_bytes());
        c.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        c.extend_from_slice(&e.ucsize.to_le_bytes());
        c.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        c.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        c.extend_from_slice(&e.attr.to_le_bytes());
        c.extend_from_slice(&off.to_le_bytes());
        c.extend_from_slice(e.name);
        cd.extend_from_slice(&c);
    }
    let cd_at = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    let n = entries.len() as u16;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// The archives the hostile runs mutate: every kind of entry the
/// extraction treats apart.
fn bases() -> Vec<Vec<u8>> {
    let text = b"the quick brown fox jumps over the lazy dog\r\n".repeat(40);
    vec![
        zip(&[
            stored(b"a.txt", b"alpha\n", 0o100644 << 16),
            deflated(b"d/b.txt", &text),
            stored(b"d/", b"", 0o40755 << 16),
            stored(b"l", b"../outside/x", 0o120777 << 16),
            stored(b"l/through.txt", b"x", 0o100644 << 16),
            stored(b"../outside/up.txt", b"up", 0o100644 << 16),
            stored(b"/abs.txt", b"abs", 0o100644 << 16),
            stored(b"ro/", b"", 0o40555 << 16),
            stored(b"ro/f", b"f", 0o100444 << 16),
            stored(b"dos.txt", b"dos\r\n", 0x21),
        ]),
        zip(&[
            E {
                flags: 1,
                ..stored(b"enc.txt", &[7u8; 40], 0o100644 << 16)
            },
            E {
                method: 6,
                flags: 6,
                ..stored(b"impl.txt", &[0x11u8; 64], 0o100644 << 16)
            },
            E {
                method: 1,
                ..stored(b"shrunk.txt", &[0xaau8; 64], 0o100644 << 16)
            },
            E {
                method: 9,
                ..deflated(b"d64.txt", &text)
            },
        ]),
    ]
}

/// xorshift64.
fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Every hostile run: a mutated or cut archive, extracted, tested, piped,
/// converted, junked, renamed at the question, in both flavours. No panic,
/// a flavour's exit code, and `outside/` (where the archive's names and
/// links point) stays empty.
#[test]
fn hostile_archives_never_panic_or_leave_the_root() {
    let runs: &[&[&str]] = &[
        &["-o", "a.zip"],
        &["a.zip"],
        &["-t", "a.zip"],
        &["-p", "a.zip"],
        &["-aao", "a.zip"],
        &["-jo", "a.zip"],
        &["-B", "a.zip"],
        &["-P", "pw", "-o", "a.zip"],
        &["-:", "-o", "-d", "out", "a.zip"],
        &["-f", "a.zip"],
    ];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for base in bases() {
        for round in 0..24 {
            let mut z = base.clone();
            if round > 0 {
                for _ in 0..(1 + next(&mut seed) % 6) {
                    let at = (next(&mut seed) as usize) % z.len();
                    z[at] = next(&mut seed) as u8;
                }
                if round % 5 == 0 {
                    let cut = (next(&mut seed) as usize) % z.len();
                    z.truncate(cut);
                }
            }
            for f in [Flavour::Apple, Flavour::Ubuntu] {
                for args in runs {
                    let d = Dir::new("hostile");
                    let root = d.0.join("root");
                    std::fs::write(root.join("a.zip"), &z).unwrap();
                    std::fs::write(root.join("a.txt"), b"was here\n").unwrap();
                    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
                    let (code, _, err, _) =
                        run_in_counted(f, &root, "unzip", &argv, b"y\nr\nnew.txt\nA\n", &|_| None);
                    let codes = match f {
                        Flavour::Apple => EXIT_CODES_APPLE,
                        Flavour::Ubuntu => EXIT_CODES_UBUNTU,
                    };
                    assert!(
                        codes.contains(&code),
                        "{f:?} {args:?} round {round}: exit {code}: {}",
                        String::from_utf8_lossy(&err)
                    );
                    let left: Vec<_> = std::fs::read_dir(d.0.join("outside")).unwrap().collect();
                    assert!(
                        left.is_empty(),
                        "{f:?} {args:?} round {round}: wrote outside"
                    );
                }
            }
        }
    }
}

/// `fgets()` over the run's one standard input: a line at a time, at most
/// `size - 1` bytes, the rest left for the next question; nothing at the
/// end.
#[test]
fn questions_read_standard_input_as_fgets() {
    let dir = Dir::new("fgets");
    let host = crate::compat::host::Host::Sandbox(crate::compat::host::Sandbox {
        dir: dir.0.clone(),
        stdin: Some(b"yes please\nn\nlast".to_vec()),
        stdout: Default::default(),
        budget: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1 << 20)),
        reads: Default::default(),
    });
    let env = |_: &str| None;
    let mut err = Vec::new();
    let mut uz = Uz::new(host, Flavour::Apple, &env, &mut err);
    assert!(output::fgets_answer(&mut uz));
    assert_eq!(c_str(&uz.answerbuf), b"yes pleas");
    assert!(output::fgets_answer(&mut uz));
    assert_eq!(c_str(&uz.answerbuf), b"e\n");
    assert!(output::fgets_answer(&mut uz));
    assert_eq!(c_str(&uz.answerbuf), b"n\n");
    assert!(output::fgets_filename(&mut uz));
    assert_eq!(c_str(&uz.filename), b"last");
    // the end: false, and the buffers keep what they held
    assert!(!output::fgets_answer(&mut uz));
    assert_eq!(c_str(&uz.answerbuf), b"n\n");
    assert!(!output::fgets_filename(&mut uz));
    assert_eq!(c_str(&uz.filename), b"last");
}

/// T10-8: VMS blocks shorter than what the C reads from them end the scan
/// (no panic, no VMS text); a well-formed PKWARE block of variable-length
/// records is VMS text.
#[test]
fn short_vms_blocks_are_not_vms_text() {
    let dir = Dir::new("vms");
    let host = crate::compat::host::Host::Sandbox(crate::compat::host::Sandbox {
        dir: dir.0.clone(),
        stdin: None,
        stdout: Default::default(),
        budget: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1 << 20)),
        reads: Default::default(),
    });
    let env = |_: &str| None;
    let mut err = Vec::new();
    let mut uz = Uz::new(host, Flavour::Apple, &env, &mut err);
    let block = |id: u16, data: &[u8]| {
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
        v
    };
    for ef in [
        block(0x000c, b"ab"),                        // PKWARE, under its CRC
        block(0x4d49, b"VFAB"),                      // Info-ZIP, under its header
        block(0x4d49, b"VFAB\x01\x00\xff\xffxxxx"),  // `0 -> 0 bit`, short data
        block(0x4d49, b"VFAB\x02\x00\x40\x00xxxxz"), // deflated, garbage
    ] {
        assert!(!extra::is_vms_varlen_txt(&mut uz, &ef), "{ef:?}");
    }
    // records attribute item: type 4, size 1, rectype 2 (variable)
    let items = [4u8, 0, 1, 0, 2];
    let mut data = crc(&items).to_le_bytes().to_vec();
    data.extend_from_slice(&items);
    assert!(extra::is_vms_varlen_txt(&mut uz, &block(0x000c, &data)));
    // an item that claims more than is left ends the scan
    let items = [4u8, 0, 0xff, 0x7f, 2];
    let mut data = crc(&items).to_le_bytes().to_vec();
    data.extend_from_slice(&items);
    assert!(extra::is_vms_varlen_txt(&mut uz, &block(0x000c, &data)));
}

/// `%-22s` and `%8s`.
#[test]
fn names_are_padded_as_printf_pads_them() {
    assert_eq!(pad22(b"a.txt"), [&b"a.txt"[..], &[b' '; 17]].concat());
    assert_eq!(pad22(&[b'x'; 30]), [b'x'; 30]);
}

/// R7 (fix round 1): a sandbox's 8 MiB budget spent mid-entry is a full
/// disk, for extraction, `-c`, `-p` and `-t` alike: the decoder holds the
/// window then, and the question formats into it all the same.
/// "write error (disk full?).  Continue? (y/n/^C) ", no answer: stop,
/// exit 50, with "... is probably truncated" (not from Apple's `-c`, `-p`,
/// `-t`);
/// `y`: that file is left and the run goes on.
#[test]
fn a_spent_budget_is_a_full_disk() {
    let big = vec![0u8; 9 << 20];
    let z = zip(&[
        deflated(b"big.bin", &big),
        stored(b"small.txt", b"small\n", 0o100644 << 16),
    ]);
    for f in [Flavour::Apple, Flavour::Ubuntu] {
        for args in [
            &["-o", "a.zip"][..],
            &["-c", "a.zip"],
            &["-p", "a.zip"],
            &["-t", "a.zip"],
        ] {
            for stdin in [&b""[..], b"y\n"] {
                let d = Dir::new("budget");
                let root = d.0.join("root");
                std::fs::write(root.join("a.zip"), &z).unwrap();
                let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
                let (code, out, err, _) =
                    run_in_counted(f, &root, "unzip", &argv, stdin, &|_| None);
                // under -t the "stderr" messages are on standard output
                let err = if args[0] == "-t" { out } else { err };
                let err = String::from_utf8_lossy(&err).into_owned();
                let what = format!("{f:?} {args:?} {stdin:?}: exit {code}: {err}");
                assert!(
                    err.contains("big.bin:  write error (disk full?).  Continue? (y/n/^C) "),
                    "{what}"
                );
                if stdin.is_empty() {
                    // Apple's extraction reaches the warning (its
                    // `close_outfile()` replaces the code: T10-2), its `-c`,
                    // `-p`, `-t` return first; upstream always warns
                    let warned = f == Flavour::Ubuntu || args[0] == "-o";
                    assert_eq!(
                        err.contains("big.bin is probably truncated\n"),
                        warned,
                        "{what}"
                    );
                    assert_eq!(code, 50, "{what}");
                } else {
                    assert!(!err.contains("probably truncated"), "{what}");
                    assert!([2, 50].contains(&code), "{what}");
                }
            }
        }
    }
}
