//! The gzip side of the differential harness against itself: `assert_same`
//! must notice each single kind of difference, and must name it.
//!
//! Both runs here are REFERENCE-side: real GNU gzip against a shell stub that
//! wraps it and changes exactly one observable thing. stuffr is never run.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn real_gzip() -> String {
        format!("{}/gzip", gnu_gzip_dir())
    }

    fn roundtrip() -> Roundtrip {
        // Leaked once per call; a handful of bytes in a test process.
        Roundtrip::Gzip {
            ref_gzip: Box::leak(real_gzip().into_boxed_str()),
        }
    }

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(40)
    }

    fn case<'a>(args: Vec<&'a str>, compare_output_bytes: bool) -> Case<'a> {
        Case {
            name: "gzip",
            args,
            files: vec![("a.txt", text())],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: roundtrip(),
        }
    }

    /// A directory holding one executable `gzip` script, removed on drop.
    struct Stub(PathBuf);
    impl Stub {
        fn new(tag: &str, body: &str) -> Stub {
            let dir =
                std::env::temp_dir().join(format!("stuffr-gzip-stub-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let f = dir.join("gzip");
            fs::write(&f, format!("#!/bin/bash\nG={}\n{body}\n", real_gzip())).unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
            Stub(dir)
        }
        fn dir(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The panic text of `assert_same(c, real, stub)`, or `None` if it passed.
    /// `None` too when the real gzip is absent locally (skipped, loudly).
    fn verdict(c: &Case, stub: &Stub) -> Option<Option<String>> {
        if !require_reference(Path::new(&real_gzip())) {
            return None;
        }
        let r = reference(gnu_gzip_dir(), c).unwrap();
        let s = reference(stub.dir(), c).unwrap();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(c, &r, &s)));
        Some(res.err().map(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        }))
    }

    /// `assert_same` must panic with `needle` and with exactly one difference.
    fn notices(c: &Case, stub: &Stub, needle: &str) {
        let Some(v) = verdict(c, stub) else { return };
        let msg = v.expect("assert_same did not notice the difference");
        assert!(msg.contains(needle), "message lacks {needle:?}:\n{msg}");
        assert!(
            msg.contains("in 1 way(s)"),
            "more than one difference:\n{msg}"
        );
    }

    #[test]
    fn a_transparent_stub_is_clean() {
        let stub = Stub::new("clean", "exec $G \"$@\"");
        let c = case(vec!["-k", "a.txt"], false);
        if let Some(v) = verdict(&c, &stub) {
            assert_eq!(v, None);
        }
    }

    #[test]
    fn notices_a_one_byte_stderr_difference() {
        // `Gzip:` for `gzip:` on the first stderr line, nothing else.
        let stub = Stub::new(
            "stderr",
            "exec 3>&1\n$G \"$@\" 2>&1 1>&3 | sed '1s/^g/G/' >&2\nexit ${PIPESTATUS[0]}",
        );
        let c = case(vec!["no-such-file"], true);
        notices(&c, &stub, "stderr differs");
    }

    #[test]
    fn notices_an_exit_code_difference() {
        let stub = Stub::new("exit", "$G \"$@\"\nrc=$?\nexit $((rc + 1))");
        let c = case(vec!["no-such-file"], true);
        notices(&c, &stub, "exit code: reference 1 vs stuffr 2");
    }

    #[test]
    fn notices_a_header_fname_difference_when_bytes_are_not_promised() {
        // `-n` drops FNAME and the mtime from the header; the deflate body is
        // identical and decodes, so only the header check can catch it.
        let stub = Stub::new("fname", "exec $G -n \"$@\"");
        let c = case(vec!["-k", "a.txt"], false);
        notices(&c, &stub, "gzip header (through FNAME) differs");
    }

    #[test]
    fn notices_an_output_the_reference_cannot_decode() {
        // Same header as the real output, then the CRC32 trailer zeroed: the
        // reference gzip rejects it with a crc error.
        let stub = Stub::new(
            "corrupt",
            "$G \"$@\"\nrc=$?\nf=a.txt.gz\n\
             n=$(wc -c < $f)\nT=$(mktemp)\ntouch -r $f $T\n\
             dd if=/dev/zero of=$f bs=1 seek=$((n - 8)) count=4 conv=notrunc 2>/dev/null\n\
             touch -r $T $f\nrm -f $T\nexit $rc",
        );
        let c = case(vec!["-k", "a.txt"], false);
        notices(&c, &stub, "reference gzip rejects stuffr's a.txt.gz");
    }

    #[test]
    fn stdout_is_judged_by_the_magic_not_a_name() {
        // `-c` output has no file name; a corrupt trailer must still be caught.
        let stub = Stub::new(
            "stdout",
            "T=$(mktemp)\n$G \"$@\" > $T\nrc=$?\nn=$(wc -c < $T)\n\
             head -c $((n - 8)) $T\nprintf '\\0\\0\\0\\0'\ntail -c 4 $T\nrm -f $T\nexit $rc",
        );
        let c = case(vec!["-c", "a.txt"], false);
        notices(&c, &stub, "rejects stuffr's stdout");
    }

    #[test]
    fn the_gnu_version_parses() {
        if !Path::new(&real_gzip()).exists() {
            assert!(gnu_gzip_version().is_none());
            return;
        }
        let (major, minor) = gnu_gzip_version().expect("gzip --version should parse");
        assert!(major == 1 && minor >= 12, "unexpected {major}.{minor}");
    }
}
