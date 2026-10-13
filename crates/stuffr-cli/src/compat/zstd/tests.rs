//! mod.rs unit tests: `main`'s steps after the arguments, through the
//! sandbox.

use super::*;

/// A scratch directory removed on drop.
struct Dir(std::path::PathBuf);
impl Dir {
    fn new(tag: &str) -> Dir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "stuffr-zstd-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sandbox(dir: &Dir, name: &'static str, args: &[&str]) -> (i32, String, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, _) = run_in_counted(&dir.0, name, &args, b"", &|_| None);
    // Standard output may hold a frame now that compression runs.
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn single_thread_refuses_adapt_and_rsyncable_with_exm_throw() {
    let d = Dir::new("st");
    for (opt, what) in [("--adapt", "Adaptive"), ("--rsyncable", "Rsyncable")] {
        let (code, out, err) = sandbox(&d, "zstd", &["--single-thread", opt]);
        assert_eq!((code, out.as_str()), (1, ""), "{opt}");
        assert_eq!(
            err,
            format!("zstd: error 1 : {what} mode is not compatible with single thread mode \n \n")
        );
    }
    let (code, _, err) = sandbox(
        &d,
        "zstd",
        &[
            "-v",
            "-T0",
            "--single-thread",
            "-B1K",
            "--zstd=ovlog=3",
            "--adapt",
        ],
    );
    assert_eq!(code, 1);
    assert!(
        err.ends_with(
            "Setting block size is useless in single-thread mode \n\
             Setting overlapLog is useless in single-thread mode \n\
             zstd: error 1 : Adaptive mode is not compatible with single thread mode \n \n"
        ),
        "{err}"
    );
}

#[test]
fn checks_after_the_arguments() {
    let d = Dir::new("checks");
    let (code, _, err) = sandbox(&d, "zstd", &["-d", "--show-default-cparams", "-20"]);
    assert_eq!(code, 1);
    assert_eq!(
        err,
        "Warning : compression level higher than max, reduced to 19 \n\
         error : can't use --show-default-cparams in decompression mode \n"
    );
    let (code, _, err) = sandbox(&d, "zstd", &["-D", "a", "--patch-from=b", "--ultra", "-23"]);
    assert_eq!(code, 1);
    assert_eq!(
        err,
        "Warning : compression level higher than max, reduced to 22 \n\
         error : can't use -D and --patch-from=# at the same time \n"
    );
    let (code, _, err) = sandbox(&d, "zstd", &["--patch-from=b", "x", "y"]);
    assert_eq!(
        (code, err.as_str()),
        (1, "error : can't use --patch-from=# on multiple files \n")
    );
    // The fake console flags reach the console checks.
    let (code, _, err) = sandbox(&d, "zstd", &["--fake-stdin-is-console"]);
    assert_eq!((code, err.as_str()), (1, "stdin is a console, aborting\n"));
    let (code, _, err) = sandbox(&d, "zstd", &["--fake-stdout-is-console"]);
    assert_eq!((code, err.as_str()), (1, "stdout is a console, aborting\n"));
    // ... but not when decompressing, or forced.
    let (_, _, err) = sandbox(&d, "zstd", &["-d", "--fake-stdout-is-console"]);
    assert!(!err.contains("console"), "{err}");
    let (_, _, err) = sandbox(&d, "zstd", &["-f", "--fake-stdin-is-console"]);
    assert!(!err.contains("console"), "{err}");
}

/// `-p` waits for enter where the run goes through zstdcli.c's `_end`
/// (help, a refused option, the end), not where it calls `exit`.
#[test]
fn the_pause_follows_clean_return() {
    let d = Dir::new("pause");
    let (code, out, err) = sandbox(&d, "zstd", &["-p", "-qV"]);
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (0, "1.5.7\n", "Press enter to continue... \n")
    );
    let (code, _, err) = sandbox(&d, "zstd", &["-p", "-qqY"]);
    assert_eq!((code, err.as_str()), (1, "Press enter to continue... \n"));
    let (code, _, err) = sandbox(&d, "zstd", &["-p", "-qq", "-T99999999999"]);
    assert_eq!((code, err.as_str()), (1, ""));
    let (code, _, err) = sandbox(&d, "zstd", &["-p", "--single-thread", "--adapt"]);
    assert_eq!(code, 1);
    assert!(!err.contains("Press enter"), "{err}");
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_ignored_without_follow_links() {
    let d = Dir::new("links");
    std::fs::write(d.0.join("a"), b"x").unwrap();
    std::os::unix::fs::symlink("a", d.0.join("l")).unwrap();
    let (code, out, err) = sandbox(&d, "zstd", &["l"]);
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (1, "", "Warning : l is a symbolic link, ignoring \n")
    );
    let (_, _, err) = sandbox(&d, "zstd", &["-q", "l", "a", "--patch-from=x", "-D", "y"]);
    assert_eq!(
        err,
        "error : can't use -D and --patch-from=# at the same time \n"
    );
}

/// `--show-default-cparams` and display level 4 print before the
/// operation (zstdcli.c:1590-1600, fileio.c's FIO_displayCompressionParameters).
#[test]
fn compression_parameters_print_before_compressing() {
    let d = Dir::new("cparams");
    std::fs::write(d.0.join("a"), vec![0u8; 5000]).unwrap();
    let (_, _, err) = sandbox(&d, "zstd", &["--show-default-cparams", "-19", "a"]);
    let mut want = Vec::new();
    cli::print_default_cparams(&mut want, b"a", Some(5000), 0, 19);
    assert!(
        err.starts_with(std::str::from_utf8(&want).unwrap()),
        "{err}"
    );
    assert!(
        err.contains(": 13\n") && err.contains("ZSTD_btultra2 (9)\n"),
        "{err}"
    );
    let (_, _, err) = sandbox(
        &d,
        "zstd",
        &[
            "-vvvv",
            "--row-match-finder",
            "--compress-literals",
            "--check",
            "-T3",
            "a",
        ],
    );
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines[1], "Compressing with 3 worker threads ", "{err}");
    assert_eq!(
        lines[2],
        "--zstd=wlog=13,clog=13,hlog=14,slog=2,mml=4,tlen=0,strat=2"
    );
    // The reference's own line for these options (`-T3`, capped at 2 by
    // the sandbox's R9 bound).
    assert_eq!(
        lines[3],
        "--format=.zst --no-sparse --check --block-size=0 --no-row-match-finder \
         --compress-literals --memory=134217728 --threads=2 --content-size"
    );
}

/// R9: a sandboxed `--train*` loads at most 256 KiB of samples (and runs
/// at most 4 optimiser steps on 2 threads); the pure tier answers as a
/// `ZSTD_NODICT` build.
#[test]
fn sandboxed_training_is_bounded() {
    let d = Dir::new("train");
    let mut names = Vec::new();
    for i in 0..40 {
        let name = format!("s{i:02}");
        let body: Vec<u8> = (0..16_000u32)
            .map(|k| b"abcdefgh ijklmnop"[((k * 7 + i) % 17) as usize])
            .collect();
        std::fs::write(d.0.join(&name), body).unwrap();
        names.push(name);
    }
    let mut args = vec![
        "--train-fastcover=steps=1000".to_string(),
        "-T8".into(),
        "-o".into(),
        "dict".into(),
    ];
    args.extend(names);
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) = run_in_counted(&d.0, "zstd", &args, b"", &|_| None);
    let err = String::from_utf8(err).unwrap();
    assert!(out.is_empty());
    if cfg!(feature = "zstd-c") {
        assert_eq!(code, 0, "{err}");
        assert!(
            err.contains("Training samples set too large (0 MB); training on 0 MB only...\n"),
            "{err}"
        );
        let read: u64 = reads.values().map(|r| r.bytes).sum();
        assert!(read <= 256 << 10, "{read} bytes of samples read");
        let dict = std::fs::read(d.0.join("dict")).unwrap();
        assert_eq!(&dict[..4], &[0x37, 0xa4, 0x30, 0xec]);
    } else {
        // Not an option in a ZSTD_NODICT build: badUsage, exit 1.
        assert_eq!(code, 1);
        assert!(
            err.starts_with(
                "Incorrect parameter: --train-fastcover=steps=1000 \nCompress or decompress"
            ),
            "{err}"
        );
        let (code, _, err) = sandbox(&d, "zstd", &["--train", "s00", "s01"]);
        assert_eq!((code, err.as_str()), (1, "training mode not available \n"));
    }
}
