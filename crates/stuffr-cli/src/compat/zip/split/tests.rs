use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::compat::host::{Host, InputReads, Sandbox};
use crate::compat::zip::Flavour;

/// A scratch directory, removed on drop (`stuffr-zipsplit-<pid>-<tag>-<n>`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("stuffr-zipsplit-{}-{tag}-{n}", std::process::id()));
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

struct Ran {
    code: i32,
    out: String,
    reads: BTreeMap<PathBuf, InputReads>,
}

/// `zip args` in a sandbox over `dir`, standard input `stdin`, an output
/// budget of `budget` bytes.
fn run(dir: &Path, flavour: Flavour, args: &[&str], stdin: &[u8], budget: u64) -> Ran {
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(budget)),
        reads: reads.clone(),
    });
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let env = |_: &str| None;
    let mut err = Vec::new();
    let code = crate::compat::zip::main(flavour, "zip", b"zip", &args, &env, host, &mut err);
    let out = String::from_utf8_lossy(&stdout.lock().unwrap()).into_owned();
    let reads = reads.lock().unwrap().clone();
    Ran { code, out, reads }
}

/// Bytes that do not compress (xorshift).
fn noise(n: usize, mut seed: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 24) as u8
        })
        .collect()
}

/// A directory with `a.txt` and 140000 bytes of `big`, split by the
/// sandbox's own zip into `s.z01`, `s.z02`, `s.zip`.
fn split_set(tag: &str, flavour: Flavour) -> Scratch {
    let s = Scratch::new(tag);
    std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(s.0.join("big"), noise(140_000, 7)).unwrap();
    let r = run(
        &s.0,
        flavour,
        &["-X", "-s", "64k", "s.zip", "big", "a.txt"],
        b"",
        u64::MAX,
    );
    assert_eq!(r.code, 0, "{}", r.out);
    for p in ["s.z01", "s.z02", "s.zip"] {
        assert!(s.0.join(p).exists(), "{p}");
    }
    s
}

/// Every part of a split archive `-F`, `-FF` and a copy read is opened
/// through `Host::track`, and read about once.
#[test]
fn split_parts_are_read_through_track() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        for args in [
            &["-F", "s.zip", "--out", "f.zip"][..],
            &["-FF", "s.zip", "--out", "f.zip"],
            &["s.zip", "--out", "f.zip"],
        ] {
            let s = split_set("track", flavour);
            let r = run(&s.0, flavour, args, b"", u64::MAX);
            assert_eq!(r.code, 0, "{flavour:?} {args:?}: {}", r.out);
            for p in ["s.z01", "s.z02", "s.zip"] {
                let k = s.0.join(p);
                let got = r
                    .reads
                    .get(&k)
                    .unwrap_or_else(|| panic!("{p} not read: {args:?}"));
                assert!(got.opens >= 1, "{p}");
                assert!(
                    got.bytes <= 4 * got.len + 0x40000,
                    "{flavour:?} {args:?} {p}: {} of {}",
                    got.bytes,
                    got.len
                );
            }
        }
    }
}

/// The end of standard input at a question about a missing part answers
/// `q` (ruling Z5); `-FF`'s single-disk question at the end is "no".
#[test]
fn questions_end_with_standard_input() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = split_set("eof", flavour);
        std::fs::remove_file(s.0.join("s.z02")).unwrap();
        let r = run(
            &s.0,
            flavour,
            &["-F", "s.zip", "--out", "f.zip"],
            b"",
            u64::MAX,
        );
        assert_eq!(r.code, 9, "{}", r.out);
        assert!(
            r.out
                .ends_with("zip error: Interrupted (Could not find split)\n"),
            "{}",
            r.out
        );
        let r = run(
            &s.0,
            flavour,
            &["-FF", "s.zip", "--out", "f.zip"],
            b"",
            u64::MAX,
        );
        assert_eq!(r.code, 9, "{}", r.out);
        // a damaged archive, a missing one
        std::fs::write(s.0.join("g.zip"), b"PK\x03\x04garbage").unwrap();
        for a in ["g.zip", "nosuch.zip"] {
            let r = run(&s.0, flavour, &["-FF", a, "--out", "f.zip"], b"", u64::MAX);
            assert_eq!(r.code, 0, "{a}: {}", r.out);
            assert!(r.out.contains("could not find split: "), "{a}: {}", r.out);
        }
    }
}

/// `-s`, `-sp` (answers from the sandbox's standard input) and an output
/// budget that runs out mid-split: every part made in the sandbox's
/// directory, no panic, an exit code of the family's.
#[test]
fn splits_are_written_in_a_sandbox() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("write");
        std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
        let r = run(
            &s.0,
            flavour,
            &["-s", "64k", "-sp", "-sv", "t.zip", "big"],
            b"\n\n\n",
            u64::MAX,
        );
        assert_eq!(r.code, 0, "{}", r.out);
        assert_eq!(r.out.matches("Opening disk").count(), 3, "{}", r.out);
        for p in ["t.z01", "t.z02", "t.z03", "t.zip"] {
            assert!(s.0.join(p).exists(), "{p}");
        }
        for budget in [1000, 70_000, 150_000] {
            let s = Scratch::new("budget");
            std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
            let r = run(&s.0, flavour, &["-s", "64k", "t.zip", "big"], b"", budget);
            // the write error (the budget is stdout's too: its message is
            // lost)
            assert_eq!(r.code, 14, "{budget}: {}", r.out);
        }
    }
}

/// `-FF` over hostile bytes ends: signatures everywhere, and a descriptor
/// search over thousands of descriptor signatures whose sizes never agree
/// (each a step back over what it read: work bounded by the input's
/// length times a read).
#[test]
fn ff_over_hostile_bytes_ends() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("hostile");
        let mut sigs = Vec::new();
        for i in 0..20_000u32 {
            sigs.extend_from_slice(b"PK\x03\x04");
            sigs.extend_from_slice(&i.to_le_bytes());
        }
        std::fs::write(s.0.join("a.zip"), &sigs).unwrap();
        // a local header with a data descriptor, then descriptor signatures
        let mut d = b"PK\x03\x04\x14\x00\x08\x00\x08\x00".to_vec();
        d.extend_from_slice(&[0; 16]);
        d.extend_from_slice(&[1, 0, 0, 0]);
        d.push(b'x');
        for _ in 0..4096 {
            d.extend_from_slice(b"PK\x07\x08");
        }
        std::fs::write(s.0.join("d.zip"), &d).unwrap();
        for a in ["a.zip", "d.zip"] {
            for args in [
                &["-FF", "-q", a, "--out", "f.zip"][..],
                &["-FF", a, "--out", "f.zip"],
            ] {
                let r = run(&s.0, flavour, args, b"y\n", 8 << 20);
                assert_eq!(r.code, 0, "{args:?}: {}", r.out);
            }
        }
    }
}

/// Ruling Z22: `-FF`'s work over hostile archives of a size that would
/// show quadratic growth (1 MiB): central headers after every local header
/// (a sort each), runs of descriptor signatures whose sizes never agree
/// (a step back each), signatures one byte apart. Reads stay linear and
/// the runs end in seconds.
#[test]
fn ff_work_is_linear_in_the_archive() {
    let flavour = Flavour::Apple;
    let s = Scratch::new("linear");
    // local header + central header, alternating, every name distinct
    let mut alt = Vec::new();
    let mut i = 0u32;
    while alt.len() < 1 << 20 {
        let name = format!("{i:08}");
        let mut lh = b"PK\x03\x04\x0a\x00\x00\x00\x00\x00".to_vec();
        lh.extend_from_slice(&[0; 16]);
        lh.extend_from_slice(&8u16.to_le_bytes());
        lh.extend_from_slice(&[0, 0]);
        lh.extend_from_slice(name.as_bytes());
        alt.extend_from_slice(&lh);
        let mut ch = b"PK\x01\x02".to_vec();
        ch.extend_from_slice(&[0; 24]);
        ch.extend_from_slice(&8u16.to_le_bytes());
        ch.extend_from_slice(&[0; 12]);
        ch.extend_from_slice(name.as_bytes());
        alt.extend_from_slice(&ch);
        i += 1;
    }
    std::fs::write(s.0.join("alt.zip"), &alt).unwrap();
    // an entry with a descriptor, then fake descriptor signatures
    let mut fake = b"PK\x03\x04\x14\x00\x08\x00\x00\x00".to_vec();
    fake.extend_from_slice(&[0; 16]);
    fake.extend_from_slice(&[1, 0, 0, 0]);
    fake.push(b'x');
    while fake.len() < 1 << 20 {
        fake.extend_from_slice(b"PK\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c");
    }
    std::fs::write(s.0.join("fake.zip"), &fake).unwrap();
    // signatures one byte apart
    let mut near = fake[..31].to_vec();
    while near.len() < 1 << 20 {
        near.extend_from_slice(b"xPK\x07\x08");
    }
    std::fs::write(s.0.join("near.zip"), &near).unwrap();
    for a in ["alt.zip", "fake.zip", "near.zip"] {
        let t = std::time::Instant::now();
        let r = run(
            &s.0,
            flavour,
            &["-FF", "-q", a, "--out", "f.zip"],
            b"",
            1 << 30,
        );
        let took = t.elapsed();
        assert_eq!(r.code, 0, "{a}: {}", r.out);
        let got = &r.reads[&s.0.join(a)];
        assert!(
            got.bytes <= 2 * got.len + (1 << 20),
            "{a}: read {} of {}",
            got.bytes,
            got.len
        );
        assert!(took < std::time::Duration::from_secs(20), "{a}: {took:?}");
    }
}

/// Ruling Z21 (deviation 20): `--out` naming the damaged archive another
/// way is refused before anything is written, the archive untouched.
#[test]
fn fix_never_replaces_its_input() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("same");
        let damaged = b"PK\x03\x04 not much of an archive".to_vec();
        std::fs::write(s.0.join("a.zip"), &damaged).unwrap();
        std::fs::hard_link(s.0.join("a.zip"), s.0.join("h.zip")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.zip", s.0.join("l.zip")).unwrap();
        for fix in ["-F", "-FF"] {
            for out in ["./a.zip", "h.zip", "l.zip"] {
                let r = run(
                    &s.0,
                    flavour,
                    &[fix, "a.zip", "--out", out],
                    b"y\n",
                    u64::MAX,
                );
                assert_eq!(r.code, 16, "{fix} {out}: {}", r.out);
                assert!(
                    r.out.ends_with(&format!(
                        "zip error: Invalid command arguments (--out path must be different than in path: {out})\n"
                    )),
                    "{fix} {out}: {}",
                    r.out
                );
                assert_eq!(std::fs::read(s.0.join("a.zip")).unwrap(), damaged);
            }
        }
    }
}

/// Ruling Z23 (deviation 21): what did not fit cannot be written to the
/// next split: both `-s` and `-sp` end with "Not enough room on disk",
/// exit 14 (`-sp` warns first, and asks no more).
#[test]
fn a_split_that_cannot_take_the_rest_ends_the_run() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        for sp in [false, true] {
            let s = Scratch::new("room");
            std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
            let mut args = vec!["-s", "64k"];
            if sp {
                args.push("-sp");
            }
            args.extend(["t.zip", "big"]);
            super::FAIL_SPLIT_REST.with(|f| f.set(true));
            let r = run(&s.0, flavour, &args, b"\n\n\n\n", u64::MAX);
            super::FAIL_SPLIT_REST.with(|f| f.set(false));
            assert_eq!(r.code, 14, "{sp}: {}", r.out);
            assert!(
                r.out
                    .ends_with("zip error: Output file write failure (Not enough room on disk)\n"),
                "{sp}: {}",
                r.out
            );
            assert_eq!(
                r.out.contains("\tzip warning: Not enough room on disk\n"),
                sp,
                "{}",
                r.out
            );
            assert_eq!(r.out.matches("Opening disk").count(), usize::from(sp));
        }
    }
}

/// Ruling Z24 (deviation 22): `-sp` with an archive name without a
/// directory takes it as a name in the current directory.
#[test]
fn sp_with_a_bare_archive_name_keeps_the_name() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("bare");
        std::fs::write(s.0.join("big"), noise(200_000, 3)).unwrap();
        std::fs::create_dir(s.0.join("o")).unwrap();
        let r = run(
            &s.0,
            flavour,
            &["-s", "64k", "-sp", "t.zip", "big"],
            b"o/\n\n\n\n",
            u64::MAX,
        );
        assert_eq!(r.code, 0, "{}", r.out);
        assert!(r.out.contains("Writing to:\n  o/\n"), "{}", r.out);
        for p in ["t.z01", "o/t.z02", "o/t.z03", "o/t.zip"] {
            assert!(s.0.join(p).is_file(), "{p}: {}", r.out);
        }
        assert!(!s.0.join("t.zip").exists());
    }
}

/// Ruling Z25 (deviation 23): an empty first `-z` line is the comment
/// `\r\n` in both flavours (Apple's build; Ubuntu's dies of glibc's
/// buffer-overflow check).
#[test]
fn an_empty_first_comment_line_is_apples_answer() {
    for flavour in [Flavour::Apple, Flavour::Ubuntu] {
        let s = Scratch::new("zcomment");
        std::fs::write(s.0.join("a.txt"), b"hello\n").unwrap();
        let r = run(&s.0, flavour, &["-z", "t.zip", "a.txt"], b"\n.\n", u64::MAX);
        assert_eq!(r.code, 0, "{}", r.out);
        let b = std::fs::read(s.0.join("t.zip")).unwrap();
        assert!(b.ends_with(b"\x02\x00\r\n"), "{:?}", &b[b.len() - 8..]);
    }
}

/// Item 1 of the fix round: each `-sp` question (and `-sb`'s bell before
/// it) is on `mesg`, flushed, before its answer is read (fprintf, fflush,
/// fgets).
#[test]
fn sp_questions_are_written_before_their_answers_are_read() {
    use std::cell::RefCell;
    use std::io::{self, BufRead, Read, Write};
    use std::rc::Rc;

    #[derive(Clone)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    /// Answers ENTER, noting at each read what `mesg` showed by then.
    struct Answers {
        mesg: Arc<Mutex<Vec<u8>>>,
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
        left: usize,
        line: Vec<u8>,
    }
    impl Read for Answers {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = {
                let b = self.fill_buf()?;
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                n
            };
            self.consume(n);
            Ok(n)
        }
    }
    impl BufRead for Answers {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.line.is_empty() && self.left > 0 {
                self.left -= 1;
                self.seen
                    .borrow_mut()
                    .push(self.mesg.lock().unwrap().clone());
                self.line = b"\n".to_vec();
            }
            Ok(&self.line)
        }
        fn consume(&mut self, n: usize) {
            self.line.drain(..n);
        }
    }

    let s = Scratch::new("order");
    let mesg = Arc::new(Mutex::new(Vec::new()));
    let seen = Rc::new(RefCell::new(Vec::new()));
    let env = super::SplitEnv {
        dir: Some(s.0.clone()),
        budget: None,
    };
    let (name, r) = crate::compat::zip::sink::mkstemp_with(false, &|b: &[u8]| env.path(b), b"");
    let (f, guard) = r.unwrap();
    let mut out = crate::compat::zip::zipfile::ZOut::new(
        Box::new(crate::compat::zip::sink::FileSink::new(f, None)),
        -1,
        None,
    );
    out.split_size = 64 * 1024;
    let reader: Box<dyn BufRead> = Box::new(Answers {
        mesg: mesg.clone(),
        seen: seen.clone(),
        left: 8,
        line: Vec::new(),
    });
    out.split = Some(Box::new(super::SplitW {
        method: 2,
        bell: true,
        noisy_splits: true,
        out_path: b"t.zip".to_vec(),
        temp_dir: Vec::new(),
        env,
        tempzip: name,
        guard: Some(guard),
        published: false,
        local: None,
        lost: Vec::new(),
        zip_attributes: 0,
        prompt: Some(Rc::new(RefCell::new(reader))),
        fnmax: 1024,
        mesg: Some(std::io::BufWriter::new(
            Box::new(Shared(mesg.clone())) as Box<dyn Write + Send>
        )),
        noisy: true,
        line: Rc::new(std::cell::Cell::new(false)),
    }));
    let chunk = noise(16 * 1024, 9);
    for _ in 0..12 {
        out.bfwrite(&chunk, crate::compat::zip::zipfile::Bf::Data)
            .unwrap();
    }
    let seen = seen.borrow();
    assert_eq!(seen.len(), 2, "two splits opened past the first");
    for (i, m) in seen.iter().enumerate() {
        let text = String::from_utf8_lossy(m);
        assert!(
            text.ends_with("\nPath (or hit ENTER to continue): "),
            "question {i} not shown before its answer: {text:?}"
        );
        let disk = format!("\x07\nOpening disk {}\n", i + 2);
        assert!(text.contains(&disk), "bell and question {i}: {text:?}");
    }
}
