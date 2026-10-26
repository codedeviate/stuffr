//! `zipcloak` and `zip -e` in a sandbox, the passwords typed through
//! `ttyio::TYPED` (a sandbox has no terminal: nothing typed is the C's
//! "stderr is not a tty"). The references need a terminal for every
//! answer here; `tests/compat_zip_tty.rs` compares them under a pty.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use stuffr::infozip::crypt::Keys;

use crate::compat::host::InputReads;
use crate::compat::zip::{Flavour, run_in_counted};

/// A scratch directory, removed on drop (`stuffr-zipcloak-<pid>-<tag>-<n>`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("stuffr-zipcloak-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }

    fn write(&self, name: &str, b: &[u8]) {
        std::fs::write(self.0.join(name), b).unwrap();
    }

    /// The names in the directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a run gave: exit, stdout, stderr, what each input read.
struct Ran {
    code: i32,
    out: String,
    err: String,
    reads: BTreeMap<PathBuf, InputReads>,
}

/// `name args` over `dir` in `flavour`, `typed` answering the prompts in
/// order (fewer answers than prompts: no terminal for the rest).
fn run(dir: &Path, flavour: Flavour, name: &str, args: &[&str], typed: &[&str]) -> Ran {
    super::super::ttyio::TYPED.with(|t| {
        let mut t = t.borrow_mut();
        t.clear();
        t.extend(typed.iter().map(|s| s.as_bytes().to_vec()));
    });
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = run_in_counted(flavour, dir, name, &args, b"");
    super::super::ttyio::TYPED.with(|t| t.borrow_mut().clear());
    Ran {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
        reads,
    }
}

/// A refusal: arguments, answers typed, exit, stdout, stderr.
type Refusal = (
    &'static [&'static str],
    &'static [&'static str],
    i32,
    &'static str,
    &'static str,
);

/// zipcloak's `   copying: name` line (its message, padded as the C's).
fn copying(name: &str) -> String {
    let mut l = Vec::new();
    crate::compat::zip::messages::printf(
        &mut l,
        crate::compat::zip::messages::CLOAK_COPYING,
        &[name.as_bytes()],
    );
    String::from_utf8(l).unwrap()
}

const FLAVOURS: [Flavour; 2] = [Flavour::Apple, Flavour::Ubuntu];

/// `a.txt` (stored) and `b.txt` (deflated) and a plain `t.zip` of them.
fn with_plain(tag: &str, flavour: Flavour) -> Scratch {
    let s = Scratch::new(tag);
    s.write("a.txt", b"hello\n");
    let b: Vec<u8> = (1..=50)
        .flat_map(|i| format!("line {i} of the b file, some text to compress\n").into_bytes())
        .collect();
    s.write("b.txt", &b);
    let r = run(
        &s.0,
        flavour,
        "zip",
        &["-q", "t.zip", "a.txt", "b.txt"],
        &[],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    s
}

/// The central directory's (flags, compressed size) per entry.
fn central(b: &[u8]) -> Vec<(u16, u32)> {
    let le16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let le32 = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let eocd = (0..=b.len() - 22)
        .rev()
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))
        .unwrap();
    let (n, mut at) = (le16(eocd + 10), le32(eocd + 16) as usize);
    let mut v = Vec::new();
    for _ in 0..n {
        assert!(b[at..].starts_with(b"PK\x01\x02"));
        v.push((le16(at + 8), le32(at + 20)));
        at += 46
            + usize::from(le16(at + 28))
            + usize::from(le16(at + 30))
            + usize::from(le16(at + 32));
    }
    v
}

/// The encryption headers of the archive's encrypted entries (each
/// entry's first 12 data bytes, found through its local header).
fn headers(b: &[u8]) -> Vec<[u8; 12]> {
    let le16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let le32 = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let eocd = (0..=b.len() - 22)
        .rev()
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))
        .unwrap();
    let (n, mut at) = (le16(eocd + 10), le32(eocd + 16) as usize);
    let mut v = Vec::new();
    for _ in 0..n {
        if le16(at + 8) & 1 != 0 {
            let lh = le32(at + 42) as usize;
            let ds = lh + 30 + usize::from(le16(lh + 26)) + usize::from(le16(lh + 28));
            v.push(b[ds..ds + 12].try_into().unwrap());
        }
        at += 46
            + usize::from(le16(at + 28))
            + usize::from(le16(at + 30))
            + usize::from(le16(at + 32));
    }
    v
}

/// A password (`wN`) whose check byte is wrong for every header: zipbare's
/// one-byte check lets one in 256 wrong passwords through.
fn failing_password(b: &[u8], right: &[u8]) -> String {
    let want: Vec<u8> = headers(b)
        .iter()
        .map(|h| {
            let mut k = Keys::new(right);
            h.iter().fold(0, |_, &c| k.decrypt_byte(c))
        })
        .collect();
    (0..)
        .map(|i| format!("w{i}"))
        .find(|pw| {
            headers(b).iter().zip(&want).all(|(h, &w)| {
                let mut k = Keys::new(pw.as_bytes());
                h.iter().fold(0, |_, &c| k.decrypt_byte(c)) != w
            })
        })
        .unwrap()
}

/// Encrypting an archive then decrypting it gives the archive back byte
/// for byte; in between every entry is encrypted (flag bit 0, 12 bytes
/// larger), the prompts are on standard error, the messages on standard
/// output, no temporary is left, and every archive read is tracked.
#[test]
fn zipcloak_then_zipcloak_d_gives_the_archive_back() {
    for f in FLAVOURS {
        let s = with_plain("roundtrip", f);
        let plain = s.read("t.zip");
        let r = run(&s.0, f, "zipcloak", &["t.zip"], &["pw", "pw"]);
        assert_eq!(r.code, 0, "{f:?}: {}{}", r.out, r.err);
        assert_eq!(r.out, "encrypting: a.txt\nencrypting: b.txt\n");
        assert_eq!(r.err, "Enter password: \nVerify password: \n");
        assert!(
            r.reads.keys().any(|p| p.ends_with("t.zip")),
            "{:?}",
            r.reads
        );
        let enc = s.read("t.zip");
        let (pc, ec) = (central(&plain), central(&enc));
        for ((pf, ps), (ef, es)) in pc.iter().zip(&ec) {
            assert_eq!(*ef, pf | 1);
            assert_eq!(*es, ps + 12);
        }
        assert_eq!(enc.len(), plain.len() + 24);
        assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"]);
        let r = run(&s.0, f, "zipcloak", &["-d", "t.zip"], &["pw"]);
        assert_eq!(r.code, 0, "{f:?}: {}{}", r.out, r.err);
        assert_eq!(r.out, "decrypting: a.txt\ndecrypting: b.txt\n");
        assert_eq!(r.err, "Enter password: \n");
        assert!(s.read("t.zip") == plain, "{f:?}: not the original");
        assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"]);
    }
}

/// `zip -e` asks twice; the archive it writes, decrypted by zipcloak, is
/// the archive `zip` writes without `-e` (the descriptor and header gone).
#[test]
fn zip_e_writes_what_zipcloak_d_takes_back_to_the_plain_archive() {
    for f in FLAVOURS {
        let s = with_plain("zipe", f);
        let plain = s.read("t.zip");
        std::fs::remove_file(s.0.join("t.zip")).unwrap();
        let r = run(
            &s.0,
            f,
            "zip",
            &["-e", "t.zip", "a.txt", "b.txt"],
            &["pw", "pw"],
        );
        assert_eq!(r.code, 0, "{f:?}: {}{}", r.out, r.err);
        assert_eq!(
            r.out,
            "  adding: a.txt (stored 0%)\n  adding: b.txt (deflated 92%)\n"
        );
        assert_eq!(r.err, "Enter password: \nVerify password: \n");
        let enc = s.read("t.zip");
        // flags 9: encrypted, with a data descriptor (16 bytes) each
        assert!(central(&enc).iter().all(|&(fl, _)| fl & 9 == 9));
        assert_eq!(enc.len(), plain.len() + 2 * (12 + 16));
        let r = run(&s.0, f, "zipcloak", &["-d", "t.zip"], &["pw"]);
        assert_eq!(r.code, 0, "{f:?}: {}{}", r.out, r.err);
        assert!(s.read("t.zip") == plain, "{f:?}");
    }
}

/// `zip -P` to standard output (a pipe: data descriptors, deflated even
/// when it does not pay) decrypts as well: `-e`'s path with `-P`'s key.
#[test]
fn zip_p_to_a_pipe_is_encrypted_with_descriptors() {
    let s = with_plain("pipe", Flavour::Apple);
    let r = run(
        &s.0,
        Flavour::Apple,
        "zip",
        &["-P", "pw", "-", "a.txt"],
        &[],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.err, "  adding: a.txt (deflated -32%)\n");
}

/// The answers zip refuses: two that differ, an empty one (after the first
/// prompt only), and no terminal.
#[test]
fn zip_e_refuses_as_zip_does() {
    let s = with_plain("zipe-refuse", Flavour::Apple);
    let before = s.read("t.zip");
    let cases: [(&[&str], &str, &str); 3] = [
        (
            &["pw", "px"],
            "\nzip error: Invalid command arguments (password verification failed)\n",
            "Enter password: \nVerify password: \n",
        ),
        (
            &[""],
            "\nzip error: Invalid command arguments (zero length password not allowed)\n",
            "Enter password: \n",
        ),
        (
            &[],
            "\nzip error: Invalid command arguments (stderr is not a tty)\n",
            "",
        ),
    ];
    for (typed, out, err) in cases {
        for f in FLAVOURS {
            let r = run(&s.0, f, "zip", &["-e", "t.zip", "a.txt"], typed);
            assert_eq!(
                (r.code, r.out.as_str(), r.err.as_str()),
                (16, out, err),
                "{typed:?}"
            );
            assert!(s.read("t.zip") == before);
            assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"]);
        }
    }
}

/// zipcloak's refusals, in its order: "nothing to do" before any prompt,
/// then no terminal, two answers that differ, an empty password (checked
/// after the second answer); the archive untouched and the temporary
/// removed every time.
#[test]
fn zipcloak_refuses_as_zipcloak_does() {
    for f in FLAVOURS {
        let s = with_plain("refuse", f);
        let plain = s.read("t.zip");
        let cases: [Refusal; 5] = [
            (
                &["-d", "t.zip"],
                &["pw"],
                12,
                "zipcloak error: Nothing to do! (no encrypted files)\n",
                "",
            ),
            (
                &["t.zip"],
                &[],
                16,
                "zipcloak error: Invalid command arguments (stderr is not a tty (you may never see this message!))\n",
                "",
            ),
            (
                &["-d", "-O", "o.zip", "t.zip"],
                &[],
                12,
                "zipcloak error: Nothing to do! (no encrypted files)\n",
                "",
            ),
            (
                &["t.zip"],
                &["pw", "px"],
                16,
                "zipcloak error: Invalid command arguments (password verification failed)\n",
                "Enter password: \nVerify password: \n",
            ),
            (
                &["t.zip"],
                &["", ""],
                16,
                "zipcloak error: Invalid command arguments (zero length password not allowed)\n",
                "Enter password: \nVerify password: \n",
            ),
        ];
        for (args, typed, code, out, err) in cases {
            let r = run(&s.0, f, "zipcloak", args, typed);
            assert_eq!(
                (r.code, r.out.as_str(), r.err.as_str()),
                (code, out, err),
                "{f:?} {args:?}"
            );
            assert!(s.read("t.zip") == plain);
            assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"]);
        }
        // every entry encrypted: nothing to do, no prompt
        let r = run(&s.0, f, "zipcloak", &["t.zip"], &["pw", "pw"]);
        assert_eq!(r.code, 0);
        let enc = s.read("t.zip");
        let r = run(&s.0, f, "zipcloak", &["t.zip"], &["pw", "pw"]);
        assert_eq!(
            (r.code, r.out.as_str(), r.err.as_str()),
            (
                12,
                "zipcloak error: Nothing to do! (all files encrypted already)\n",
                ""
            )
        );
        assert!(s.read("t.zip") == enc);
        // a missing archive
        let r = run(&s.0, f, "zipcloak", &["nosuch.zip"], &["pw", "pw"]);
        assert_eq!(
            (r.code, r.out.as_str()),
            (
                13,
                "zipcloak error: Missing or empty zip file (nosuch.zip)\n"
            )
        );
    }
}

/// `-d` with a wrong password copies each entry as it is (exit 0); an
/// entry already encrypted is copied when encrypting; `-O` writes another
/// archive and leaves the original.
#[test]
fn zipcloak_copies_what_it_cannot_or_need_not_change() {
    for f in FLAVOURS {
        let s = with_plain("copies", f);
        let r = run(&s.0, f, "zipcloak", &["t.zip"], &["pw", "pw"]);
        assert_eq!(r.code, 0);
        let enc = s.read("t.zip");
        let wrong = failing_password(&enc, b"pw");
        let r = run(&s.0, f, "zipcloak", &["-d", "t.zip"], &[&wrong]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert_eq!(
            r.out,
            "decrypting: a.txt (wrong password--just copying)\n\
             decrypting: b.txt (wrong password--just copying)\n"
        );
        assert!(
            s.read("t.zip") == enc,
            "{f:?}: a copy is the entry as it was"
        );
        // a plain entry added beside the encrypted ones
        s.write("c.txt", b"c\n");
        let r = run(&s.0, f, "zip", &["-q", "t.zip", "c.txt"], &[]);
        assert_eq!(r.code, 0);
        let mixed = s.read("t.zip");
        let r = run(
            &s.0,
            f,
            "zipcloak",
            &["-O", "o.zip", "t.zip"],
            &["pw", "pw"],
        );
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert_eq!(
            r.out,
            format!(
                "{}{}encrypting: c.txt\n",
                copying("a.txt"),
                copying("b.txt")
            )
        );
        assert!(s.read("t.zip") == mixed, "-O leaves the archive");
        let o = s.read("o.zip");
        assert!(central(&o).iter().all(|&(fl, _)| fl & 1 == 1));
        // every entry of -O's archive decrypts
        let r = run(&s.0, f, "zipcloak", &["-d", "o.zip"], &["pw"]);
        assert_eq!(r.code, 0, "{}{}", r.out, r.err);
        assert_eq!(
            r.out,
            "decrypting: a.txt\ndecrypting: b.txt\ndecrypting: c.txt\n"
        );
        let o = s.read("o.zip");
        assert!(central(&o).iter().all(|&(fl, _)| fl & 1 == 0));
        assert_eq!(o.len(), mixed.len() - 24);
        assert_eq!(s.names(), ["a.txt", "b.txt", "c.txt", "o.zip", "t.zip"]);
    }
}

/// Hostile encrypted archives (entries shorter than their header, local
/// headers cut short or moved, sizes past the end) never panic, never
/// change the archive, and leave no temporary, whatever the answer.
#[test]
fn hostile_encrypted_archives_end_cleanly() {
    let s = with_plain("hostile", Flavour::Apple);
    let r = run(&s.0, Flavour::Apple, "zipcloak", &["t.zip"], &["pw", "pw"]);
    assert_eq!(r.code, 0);
    let enc = s.read("t.zip");
    let plain_len = enc.len();
    let le32 = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let eocd = plain_len - 22;
    let cd = le32(&enc, eocd + 16) as usize;
    let mut variants: Vec<Vec<u8>> = Vec::new();
    // compressed sizes 0..=13 and huge in the first central header
    for siz in [0u32, 1, 5, 11, 12, 13, 0x7fff_ffff, 0xffff_ffff] {
        let mut b = enc.clone();
        b[cd + 20..cd + 24].copy_from_slice(&siz.to_le_bytes());
        variants.push(b);
    }
    // the first entry's local offset past the end, or into its data
    for off in [5u32, 40, 1000, 0xffff_fff0] {
        let mut b = enc.clone();
        b[cd + 42..cd + 46].copy_from_slice(&off.to_le_bytes());
        variants.push(b);
    }
    // the data cut short: the archive's middle removed, the directory moved
    for cut in [35usize, 45, 60, 100] {
        let mut b = enc[..cut].to_vec();
        b.extend_from_slice(&enc[cd..]);
        let new_cd = (cut as u32).to_le_bytes();
        let e = b.len() - 22;
        b[e + 16..e + 20].copy_from_slice(&new_cd);
        variants.push(b);
    }
    for (i, v) in variants.iter().enumerate() {
        for (args, typed) in [
            (&["-d", "t.zip"][..], &["pw"][..]),
            (&["-d", "t.zip"], &["x"]),
        ] {
            s.write("t.zip", v);
            let r = run(&s.0, Flavour::Apple, "zipcloak", args, typed);
            assert!(r.code != 1, "variant {i}: exit 1 is stuffr's own failure");
            if r.code != 0 {
                assert!(
                    s.read("t.zip") == *v,
                    "variant {i} {args:?}: archive changed"
                );
            }
            assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"], "variant {i}");
        }
        // encrypting it (as a plain archive, flag bit 0 cleared)
        let mut p = v.clone();
        if p.len() >= 22 {
            let e = p.len() - 22;
            let cdv = le32(&p, e + 16) as usize;
            let mut at = cdv;
            while at + 46 <= e && p[at..].starts_with(b"PK\x01\x02") {
                p[at + 8] &= !1;
                at += 46
                    + usize::from(u16::from_le_bytes([p[at + 28], p[at + 29]]))
                    + usize::from(u16::from_le_bytes([p[at + 30], p[at + 31]]))
                    + usize::from(u16::from_le_bytes([p[at + 32], p[at + 33]]));
            }
        }
        s.write("t.zip", &p);
        let r = run(&s.0, Flavour::Apple, "zipcloak", &["t.zip"], &["pw", "pw"]);
        assert!(r.code != 1, "variant {i}: exit 1");
        if r.code != 0 {
            assert!(s.read("t.zip") == p, "variant {i}: archive changed");
        }
        assert_eq!(s.names(), ["a.txt", "b.txt", "t.zip"], "variant {i}");
    }
}
