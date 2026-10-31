// Unix only: it spawns `unzip` from PATH and resolves binaries without
// `.exe`, so it cannot run on Windows as written.
#![cfg(unix)]
//! The ZIP-on-a-pipe contract test — `0.2.0`'s namesake claim, pinned as its
//! own file because it is the milestone's headline demonstration.
//!
//! The claim, made falsifiable: **streaming a trailing-index format costs
//! metadata, not data — and stuffr says so honestly.** tar, ar and cpio carry
//! every entry's metadata inline, so a forward read of any of them loses
//! nothing. zip is different: its authoritative index is a central directory
//! at the END of the stream, so a forward (piped) read has to fall back to
//! local headers, which is a real, reportable loss.
//!
//! This is a black-box, end-to-end test: it spawns the real, compiled
//! `stuffr` binary against genuine OS pipes rather than calling `Zip::open`
//! directly (see [`stuffr_bin_path`] for how the binary is located — not
//! `env!("CARGO_BIN_EXE_stuffr")`, which only works within the binary's own
//! crate). `zip.rs`'s own unit tests already cover the
//! container in isolation (`open_forward_only`, backed by a `Cursor` whose
//! seek capability the harness DELIBERATELY erases). This file instead proves
//! the claim the way a user piping `curl` into stuffr would actually observe
//! it — including the parts no in-process unit test can see, like whether
//! `stuffr`'s own CLI plumbing honestly reports what it did.
//!
//! # Why this doesn't use `stuffr info --json -` for the piped read
//!
//! The task brief that seeded this file sketched `Observed::from_info_json`
//! against `stuffr info --json -`. That command's contract changed underfoot
//! during this same phase (see `fix(cli): stop claiming info evaluated an
//! archive's fidelity`, `fix(cli): withhold info's fidelity claim only where
//! loss is possible`): `stuffr info` never OPENS the archive — its `rung` is
//! only the raw source's own seekability
//! (`ops::inspect_with`: `if caps.seekable { Exact } else { ForwardOnly }`),
//! true for every piped input regardless of what a real read would do, and
//! its `warnings` are unconditionally empty for a container whose forward
//! read could lose something (`fidelity_evaluated: false`). Using it here
//! would make assertions 2 and 5 vacuous — `rung` would read
//! `ForwardOnly` even for a container that silently spills to a temp file,
//! since `info` never asks the container anything at all — and assertion 6
//! could never see a real warning.
//!
//! `stuffr test -` instead reads `Outcome { fidelity: ar.fidelity().clone(),
//! .. }` (`entries::test`), which is the container's own report AFTER
//! `ladder::resolve` has actually decided a rung and `Zip::open` has actually
//! produced its warnings — the real thing every assertion below needs.
//! `stuffr unpack - -C DIR` (`entries::extract`) supplies the entry names and
//! bytes, materialised to disk from the same forward read.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output as ProcOutput, Stdio};
use std::sync::LazyLock;

use stuffr_core::{
    Container, Fidelity, FidelityReport, FormatId, OpenOpts, ReaderSource, Rung, Source,
    StreamPolicy, resolve,
};
use stuffr_formats::zip::Zip;

const ZIP: FormatId = FormatId::new("zip");

/// The path to the compiled `stuffr` binary.
///
/// The task brief that seeded this file assumed `env!("CARGO_BIN_EXE_stuffr")`
/// would resolve it, the way `stuffr-cli/tests/cli/common.rs` does. Confirmed by
/// trying it: that only works for a crate's OWN `[[bin]]` target — Cargo does
/// NOT propagate `CARGO_BIN_EXE_<name>` across a dev-dependency edge (even
/// after declaring one on `stuffr-cli` here, the variable stayed undefined at
/// compile time for this crate's own tests, both under `--manifest-path
/// crates/stuffr-formats/Cargo.toml` and under `--workspace`). This crate is
/// not the binary's owner, so the path is derived the way Cargo's own runtime
/// environment allows instead: this test binary's `current_exe()` lives under
/// `<target-dir>/<profile>/deps/`, and `stuffr` — built for the SAME profile —
/// lives one directory up. If it is not there yet (a clean checkout that has
/// never built the CLI crate), this builds it explicitly via the `CARGO`
/// environment variable Cargo sets at runtime for exactly this kind of
/// self-reference.
static STUFFR: LazyLock<PathBuf> = LazyLock::new(stuffr_bin_path);

fn stuffr_bin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // `.../target/<profile>/deps/zip_on_a_pipe-<hash>` -> `.../target/<profile>/`
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("test binary has a target/<profile>/deps parent")
        .to_path_buf();
    let bin = profile_dir.join(format!("stuffr{}", std::env::consts::EXE_SUFFIX));
    if bin.is_file() {
        return bin;
    }

    // Not built yet: build it now, for the same profile this test binary was
    // built with, so a fresh checkout's first `cargo test -p stuffr-formats`
    // does not simply fail to find it.
    let profile_name = profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .expect("profile directory has a name");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../stuffr-cli/Cargo.toml");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "--manifest-path"])
        .arg(&manifest)
        .args(["--bin", "stuffr"]);
    match profile_name {
        "debug" => {}
        "release" => {
            cmd.arg("--release");
        }
        other => {
            cmd.args(["--profile", other]);
        }
    }
    let status = cmd.status().expect("spawn cargo build for stuffr-cli");
    assert!(status.success(), "building the stuffr binary failed");
    assert!(
        bin.is_file(),
        "expected {} to exist after building stuffr-cli",
        bin.display()
    );
    bin
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A zip written through a SEEKABLE `zip::ZipWriter` — real sizes and a real
/// crc32 in every local header, no data descriptors. This is the "written
/// seekably" scope the task narrows itself to: `zip` 8.6.0 cannot forward-read
/// an archive whose entries used data descriptors at all (see
/// `data_descriptor_zip_over_a_pipe_is_refused_honestly_not_reported_as_corrupt`
/// below), which is a real, separate gap this test does not paper over.
fn fixture_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            w.start_file(*name, opts).expect("start_file");
            w.write_all(data).expect("write entry data");
        }
        w.finish().expect("finish");
    }
    buf
}

/// A zip written through `ZipWriter::new_stream` — the writer this project's
/// own `zip.rs` refuses to use for exactly this reason (see its module doc):
/// every entry's local header carries a zero crc32 and zero sizes, with the
/// real values following the payload in a data descriptor. `zip` 8.6.0 cannot
/// forward-read this AT ALL, seekable source or not — it is a property of the
/// ARCHIVE, not of how it arrives.
fn fixture_zip_with_data_descriptors(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new_stream(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            w.start_file(*name, opts).expect("start_file");
            w.write_all(data).expect("write entry data");
        }
        w.finish().expect("finish");
    }
    buf
}

// ---------------------------------------------------------------------------
// Process plumbing
// ---------------------------------------------------------------------------

/// A private scratch directory for this test binary's process, so parallel
/// `cargo test` runs (and repeat runs) never collide.
///
/// Removes its tree on drop, a panicking test's unwind included, restoring
/// write permission on directories first.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove_tree(&self.0);
    }
}

/// Restores user rwx on every directory under `p`, never following symlinks.
// keep in sync with the copies in tests/cli/common.rs, compat_harness/mod.rs (stuffr-cli),
// src/compat/compress/test_scratch.rs (stuffr-cli), tests/zip_on_a_pipe.rs (stuffr-formats),
// tests/common/mod.rs and src/entries.rs (stuffr)
#[cfg(unix)]
fn make_dirs_writable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o700);
    let _ = std::fs::set_permissions(p, perms);
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            make_dirs_writable(&e.path());
        }
    }
}

#[cfg(not(unix))]
fn make_dirs_writable(_p: &Path) {}

fn remove_tree(p: &Path) {
    make_dirs_writable(p);
    let _ = std::fs::remove_dir_all(p);
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!(
        "stuffr-zip-on-a-pipe-{}-{name}",
        std::process::id()
    ));
    remove_tree(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn write_temp_zip(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("fixture.zip");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Runs `stuffr` with `bytes` on a REAL OS pipe as stdin.
///
/// Not a `Cursor` reporting `seekable: false` — a `Cursor` still physically
/// supports positioned reads, so a hypothetical implementation that reached
/// around the `Source` trait object (a raw downcast, say) would still succeed
/// against one. Spawning the actual binary makes the non-seekability a
/// property of the operating system: `Command::stdin(Stdio::piped())` is a
/// genuine anonymous pipe, and any attempt to seek it fails at the syscall,
/// which is the condition a user piping `curl` into `stuffr` actually meets.
///
/// Written from a separate thread: a multi-entry fixture can exceed the pipe
/// buffer, and writing inline would deadlock this test against its own child
/// (the child blocks trying to write its own output before we have started
/// reading it, while we block trying to finish writing stdin — a genuine
/// deadlock, not a slow test, so it is worth spelling out why the thread is
/// not optional).
fn run_piped(args: &[&str], bytes: &[u8]) -> ProcOutput {
    let mut child = Command::new(&*STUFFR)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stuffr");

    let mut stdin = child.stdin.take().expect("child stdin");
    let owned = bytes.to_vec();
    let writer = std::thread::spawn(move || {
        // A downstream refusal (e.g. the data-descriptor case, which stops
        // reading immediately) can close its end before every byte is
        // written; that manifests as a `BrokenPipe` here and is not this
        // helper's problem to report — the caller inspects the child's own
        // exit status and stderr instead.
        let _ = stdin.write_all(&owned);
    });

    let out = child.wait_with_output().expect("wait for stuffr");
    writer.join().expect("writer thread panicked");
    out
}

fn run_on_path(args: &[&str]) -> ProcOutput {
    Command::new(&*STUFFR)
        .args(args)
        .output()
        .expect("run stuffr")
}

// ---------------------------------------------------------------------------
// Parsing `stuffr test`'s human report
// ---------------------------------------------------------------------------

/// `entries::test`'s `Outcome.fidelity`, as printed by the CLI's `Test` arm:
/// a summary line naming the rung in parentheses, then (only if there are
/// any) a `stuffr: N fidelity warning(s):` header and one `  - MESSAGE` line
/// per warning — the exact shape `report_fidelity` in `stuffr-cli/src/
/// main.rs` writes to stderr. No `--json` exists for `test`, so this parses
/// the one output format there is; each piece is asserted rather than
/// assumed (a wrong assumption panics loudly instead of desyncing silently).
struct TestReport {
    rung: Rung,
    /// Raw warning lines, each the `Display` text of one `Fidelity` value —
    /// compared against the real enum's own `.to_string()` below rather than
    /// a hand-copied literal, so a wording change upstream cannot silently
    /// desync this test from what the type actually says.
    warnings: Vec<String>,
}

fn parse_test_report(stderr: &str) -> TestReport {
    let mut lines = stderr.lines();
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("`stuffr test` printed no summary line at all: {stderr:?}"));
    // Two shapes, because the summary line must not announce "exact fidelity"
    // over a report that carries losses (the ruling `pack`'s own summary line
    // already followed, extended to `test` when zip gained a way for an EXACT
    // read to lose something — an index that shadows its own records):
    //
    //   clean: "{format} -> {n} bytes verified ({rung} fidelity)"
    //   lossy: "{format} -> {n} bytes verified ({rung} access, {k} fidelity loss(es))"
    //
    // The rung is in both, and is what this parses. Which shape appeared is
    // then checked against `warnings` below, so the two cannot drift apart.
    // `split_once`, not `rsplit_once`: the lossy shape ends in "loss(es))",
    // so the LAST open paren is inside the count, not the one that opens the
    // parenthetical. No format name contains a paren, so the first one is
    // always the right one.
    let inside = summary
        .split_once('(')
        .and_then(|(_, tail)| tail.strip_suffix(')'))
        .unwrap_or_else(|| panic!("could not find a rung in the summary line: {summary:?}"));
    let (rung_word, summary_claims_loss) = match inside.strip_suffix(" fidelity") {
        Some(rung) => (rung, false),
        None => (
            inside
                .split_once(" access, ")
                .map(|(rung, _)| rung)
                .unwrap_or_else(|| {
                    panic!("could not find a rung in the summary line: {summary:?}")
                }),
            true,
        ),
    };
    let rung = match rung_word {
        "exact" => Rung::Exact,
        "forward-only" => Rung::ForwardOnly,
        "spilled" => Rung::Spilled,
        "degraded" => Rung::Degraded,
        other => panic!("unrecognised rung word {other:?} in {summary:?}"),
    };

    let mut warnings = Vec::new();
    for line in lines {
        if let Some(msg) = line.strip_prefix("  - ") {
            warnings.push(msg.to_owned());
        }
        // The "stuffr: N fidelity warning(s):" header and any "… and N more"
        // truncation line are deliberately ignored: this fixture never has
        // enough warnings to hit the ten-line cap, and the header's count is
        // redundant with `warnings.len()` once every bullet has been parsed.
    }
    assert_eq!(
        summary_claims_loss,
        !warnings.is_empty(),
        "the summary line and the warning list must agree about whether \
         anything was lost: {stderr:?}"
    );
    TestReport { rung, warnings }
}

// ---------------------------------------------------------------------------
// Walking an extraction directory back into (names, data)
// ---------------------------------------------------------------------------

/// Recursively lists every regular file under `root`, sorted by its relative
/// path, so the seekable and piped extractions — which may not visit entries
/// in the same order internally — compare equal on CONTENT regardless of
/// enumeration order. Sorting weakens nothing here: assertion 3 is about
/// names and bytes agreeing, not about archive order, and both sides are
/// sorted identically.
fn extracted_files(root: &Path) -> (Vec<String>, Vec<Vec<u8>>) {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();

    let mut names = Vec::new();
    let mut data = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        data.push(std::fs::read(&f).unwrap());
        names.push(rel);
    }
    (names, data)
}

// ---------------------------------------------------------------------------
// `Observed`: what both reads are compared on
// ---------------------------------------------------------------------------

/// Field-by-field rather than a blob, so a failing assertion names which
/// aspect diverged instead of dumping two whole structures at the reader.
struct Observed {
    rung: Rung,
    names: Vec<String>,
    data: Vec<Vec<u8>>,
    warnings: Vec<String>,
}

fn read_seekable(bytes: &[u8]) -> Observed {
    let dir = scratch("seekable");
    let zip_path = write_temp_zip(&dir, bytes);
    let zip_path_str = zip_path.to_str().unwrap();

    let test_out = run_on_path(&["test", zip_path_str]);
    assert!(
        test_out.status.success(),
        "seekable `stuffr test` failed: {test_out:?}"
    );
    let report = parse_test_report(&String::from_utf8_lossy(&test_out.stderr));

    let extract_dir = dir.join("out");
    let extract_dir_str = extract_dir.to_str().unwrap();
    let unpack_out = run_on_path(&["unpack", zip_path_str, "-C", extract_dir_str]);
    assert!(
        unpack_out.status.success(),
        "seekable `stuffr unpack` failed: {unpack_out:?}"
    );
    let (names, data) = extracted_files(&extract_dir);

    Observed {
        rung: report.rung,
        names,
        data,
        warnings: report.warnings,
    }
}

fn read_over_a_real_pipe(bytes: &[u8]) -> Observed {
    let dir = scratch("piped");

    let test_out = run_piped(&["test", "-"], bytes);
    assert!(
        test_out.status.success(),
        "piped `stuffr test -` failed: {test_out:?}"
    );
    let report = parse_test_report(&String::from_utf8_lossy(&test_out.stderr));

    let extract_dir = dir.join("out");
    let extract_dir_str = extract_dir.to_str().unwrap();
    let unpack_out = run_piped(&["unpack", "-", "-C", extract_dir_str], bytes);
    assert!(
        unpack_out.status.success(),
        "piped `stuffr unpack -` failed: {unpack_out:?}"
    );
    let (names, data) = extracted_files(&extract_dir);

    Observed {
        rung: report.rung,
        names,
        data,
        warnings: report.warnings,
    }
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// Reads the SAME zip twice — once from a real file, once over a real OS
/// pipe — and compares. Five assertions, each of which a plausible-but-wrong
/// implementation would fail and each independently killable by mutation
/// (see the numbered comments below and the task report's mutation table —
/// a sixth, "`piped.rung != Exact`", was tried and removed: it cannot fail
/// without the `== Rung::ForwardOnly` equality below it failing first, so it
/// was decoration rather than a second, independent check).
#[test]
fn the_same_zip_read_seekably_and_over_a_pipe_agrees_on_data_and_differs_on_rung() {
    let bytes = fixture_zip(&[
        ("a.txt", b"alpha"),
        ("b/c.bin", b"\x00\xff\x00"),
        ("empty", b""),
    ]);

    let exact = read_seekable(&bytes);
    let piped = read_over_a_real_pipe(&bytes);

    // 1 + 2: the two rungs.
    assert_eq!(
        exact.rung,
        Rung::Exact,
        "a seekable zip must use the central directory"
    );
    assert_eq!(
        piped.rung,
        Rung::ForwardOnly,
        "a piped zip must use local headers"
    );

    // 3: data is NOT lost. The half that makes streaming worth having.
    assert_eq!(
        exact.names, piped.names,
        "entry names must agree between the two reads"
    );
    assert_eq!(
        exact.data, piped.data,
        "entry DATA must be byte-identical between the two reads"
    );

    // (No separate "honesty" assertion here — a prior version of this test
    // had `assert_ne!(piped.rung, Rung::Exact)` at this point, checking the
    // module doc's "claiming Exact off local headers would pass a naive
    // round trip while lying about fidelity" concern. It is REMOVED, not
    // merely reordered: mutation-checking it (see the report) showed it
    // cannot fail independently of the `assert_eq!(piped.rung,
    // Rung::ForwardOnly)` two assertions up — that equality already rules
    // out every wrong value `piped.rung` could hold, `Exact` included, so
    // any mutation that would have tripped this one trips that one first.
    // Re-adding a bare inequality against `Exact` here would be decoration,
    // not a second, independent check; if that equality is ever weakened
    // (e.g. to `is_authoritative()` instead of an exact match), THIS is
    // where an explicit `!= Exact` would start earning its keep again.)

    // 5: no spill. Spilled is honest but DIFFERENT — conflating them would let
    //    a disk-consuming implementation pass as streaming. This is a
    //    READ-path assertion only: zip's WRITE path deliberately spools one
    //    entry at a time (a zip local header needs a crc32 the payload has
    //    not produced yet), which is unrelated and not what this checks.
    assert_ne!(
        piped.rung,
        Rung::Spilled,
        "the forward read must not spool to disk"
    );

    // 6: since ruling B2 the forward read reads the central directory at the
    //    end of the pipe and compares it with the local headers it walked.
    //    When they agree, `TrailingIndexUnread` and `EntryCountUnknown` are
    //    no longer true and are withdrawn: a well-formed piped zip reports
    //    nothing (it reported exactly those two in 0.22.0). The cut-off case
    //    keeps both: `a_piped_zip_with_a_cut_central_directory_keeps_both_warnings`
    //    below, and over the binary the cut test right after this one.
    assert!(
        piped.warnings.is_empty(),
        "a piped zip whose index was read and agrees has nothing to warn about: {:?}",
        piped.warnings
    );
    assert!(
        exact.warnings.is_empty(),
        "a seekable zip read has nothing to warn about: {:?}",
        exact.warnings
    );
}

/// The cut-off case over the binary, unchanged from 0.22.0: a pipe whose
/// central directory is cut off is corruption (exit 5), and the CLI prints
/// the error alone, as it did. The report behind it still carries both index
/// warnings (`a_piped_zip_with_a_cut_central_directory_keeps_both_warnings`).
#[test]
fn a_piped_zip_cut_inside_its_central_directory_is_still_exit_5() {
    let bytes = fixture_zip(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let (locals, _) = split_zip(&bytes);
    let out = run_piped(&["test", "-"], &bytes[..locals.len() + 20]);
    assert_eq!(out.status.code(), Some(5), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("16 bytes into a 42-byte central directory header")
            && !stderr.contains("disagree"),
        "{stderr}"
    );
}

/// A symlink entry whose target is 100 KiB, past the 64 KiB cap.
///
/// Pins an asymmetry: the central directory carries the `S_IFLNK` mode, so a
/// seekable read sees a symlink and refuses the over-long target
/// (`Error::ResourceLimit`, exit 6). Local headers carry no mode, so a piped
/// read sees a regular file holding the target text, streamed, and the cap
/// never applies.
#[test]
fn a_piped_zip_reads_a_symlink_as_a_plain_file_past_the_target_cap() {
    let target = "t".repeat(100 * 1024);
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.add_symlink("link", &target, opts).expect("add_symlink");
        w.start_file("plain.txt", opts).expect("start_file");
        w.write_all(b"plain").expect("write");
        w.finish().expect("finish");
    }

    // Piped: a regular file holding the target text.
    let dir = scratch("piped-symlink");
    let out_dir = dir.join("out");
    let out_str = out_dir.to_str().unwrap();
    let piped = run_piped(&["unpack", "-", "-C", out_str], &buf);
    assert!(piped.status.success(), "piped unpack failed: {piped:?}");
    let meta = std::fs::symlink_metadata(out_dir.join("link")).expect("link entry extracted");
    assert!(
        meta.file_type().is_file(),
        "a piped symlink entry must become a regular file, got {:?}",
        meta.file_type()
    );
    assert_eq!(
        std::fs::read(out_dir.join("link")).unwrap(),
        target.as_bytes(),
        "the regular file must hold the target text"
    );
    assert_eq!(std::fs::read(out_dir.join("plain.txt")).unwrap(), b"plain");

    // Seekable: the same bytes are a symlink with an over-long target.
    let sdir = scratch("seekable-symlink");
    let zip_path = write_temp_zip(&sdir, &buf);
    let sout = sdir.join("out");
    let seek = run_on_path(&[
        "unpack",
        zip_path.to_str().unwrap(),
        "-C",
        sout.to_str().unwrap(),
    ]);
    assert_eq!(
        seek.status.code(),
        Some(6),
        "a seekable read must refuse the 100 KiB symlink target (exit 6): {seek:?}"
    );
}

/// The write direction, with an external arbiter — the precedent being system
/// `xz` validating what `lzma-rust2` writes. `unzip` is required to be on
/// `PATH` (via `require_bin`, panicking rather than skipping): a missing
/// reference tool must not let this test report a pass having verified
/// nothing.
#[test]
fn a_zip_written_to_a_pipe_is_accepted_by_system_unzip() {
    let unzip = require_bin("unzip");

    let src_dir = scratch("write-src");
    std::fs::write(src_dir.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src_dir.join("b.txt"), b"beta").unwrap();

    // `pack a.txt b.txt --format zip -o -` writes the archive to its own
    // stdout, which `Stdio::piped()` backs with a genuine OS pipe — this is
    // the write-side counterpart of `run_piped` above, just driven by
    // `Command::output()` since nothing needs to be written to the CHILD's
    // stdin here.
    let out = Command::new(&*STUFFR)
        .args(["pack", "a.txt", "b.txt", "--format", "zip", "-o", "-"])
        .current_dir(&src_dir)
        .output()
        .expect("run stuffr pack");
    assert!(
        out.status.success(),
        "stuffr pack to a pipe failed: {out:?}"
    );
    let produced = out.stdout;

    let zip_path = src_dir.join("produced.zip");
    std::fs::write(&zip_path, &produced).unwrap();

    let t = Command::new(&unzip)
        .arg("-t")
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(
        t.status.success(),
        "system unzip -t rejected our streamed zip: {t:?}"
    );

    let extracted = Command::new(&unzip)
        .args(["-p"])
        .arg(&zip_path)
        .arg("b.txt")
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "unzip -p b.txt failed: {extracted:?}"
    );
    assert_eq!(
        extracted.stdout, b"beta",
        "system unzip extracted different bytes than we wrote"
    );
}

/// Scope note made concrete: `zip` 8.6.0 cannot forward-read an archive whose
/// entries used data descriptors, which is what a genuinely streaming zip
/// writer (one with no seek at all, e.g. `ZipWriter::new_stream`) has to
/// produce — a local header cannot carry a real crc32 or size before the
/// payload has been compressed. The contract above deliberately narrows
/// itself to zips WRITTEN SEEKABLY; this test is the other half, proving the
/// narrowing is not silently absolute. The honest outcome here is a refusal
/// (`Error::Unsupported`, exit 3, with a hint) — never a claim of corruption
/// (exit 5) and never a silent success.
#[test]
fn data_descriptor_zip_over_a_pipe_is_refused_honestly_not_reported_as_corrupt() {
    let bytes = fixture_zip_with_data_descriptors(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);

    let out = run_piped(&["test", "-"], &bytes);

    assert_eq!(
        out.status.code(),
        Some(3),
        "a data-descriptor zip over a pipe must be refused as unsupported (exit 3), \
         not corrupt (exit 5) or a generic failure (exit 1): {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("data descriptor"),
        "the refusal must hint at WHY: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("corrupt"),
        "a data-descriptor zip is not damaged; calling it corrupt would send a user chasing a \
         bad download that isn't one: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

/// Locates `bin` on `PATH`, panicking rather than silently skipping if it is
/// absent — the same strict pattern `zip.rs`, `ar.rs` and `cpio.rs` already
/// use for their own cross-implementation tests. `unzip` ships on every
/// platform CI runs on, so an absence here means only a contributor's own
/// machine lacks it, and a silent `return` would report this test as PASSING
/// having verified nothing at all.
fn require_bin(bin: &str) -> PathBuf {
    which(bin).unwrap_or_else(|| {
        panic!(
            "no reference `{bin}` tool found on PATH — this test proved nothing, which is worth \
             knowing rather than passing silently"
        )
    })
}

// ---------------------------------------------------------------------------
// The central directory, read and compared at the end of the pipe (spec goal
// 2, rulings B2 and B3), in process over a `ReaderSource`
// ---------------------------------------------------------------------------

/// Walks `bytes` as a pipe through `Zip`, reading every payload, and returns
/// how the walk ended with the report as it stood then.
fn walk_piped(bytes: &[u8]) -> (stuffr_core::Result<usize>, FidelityReport) {
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())));
    let resolved = resolve(src, ZIP, Zip.caps(), &StreamPolicy::default()).expect("resolve");
    let mut ar = Zip.open(resolved, &OpenOpts::default()).expect("open");
    let mut n = 0;
    let end = loop {
        match ar.next_entry() {
            Ok(Some(mut e)) => {
                let mut sink = Vec::new();
                if let Err(err) = std::io::Read::read_to_end(&mut e.reader(), &mut sink) {
                    break Err(stuffr_core::Error::from_decode_io(err));
                }
                n += 1;
            }
            Ok(None) => break Ok(n),
            Err(e) => break Err(e),
        }
    };
    (end, ar.fidelity().clone())
}

fn index_warnings(report: &FidelityReport) -> (bool, bool) {
    (
        report
            .warnings
            .contains(&Fidelity::TrailingIndexUnread { format: ZIP }),
        report.warnings.contains(&Fidelity::EntryCountUnknown),
    )
}

fn disagreements(report: &FidelityReport) -> Vec<(String, &'static str)> {
    report
        .warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::HeadersDisagree { entry, field, .. } => Some((entry.clone(), *field)),
            _ => None,
        })
        .collect()
}

fn le16(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

/// A comment-free zip split into its local section (everything before the
/// central directory) and its central records, each whole.
fn split_zip(bytes: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let eocd = bytes.len() - 22;
    assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06", "a comment-free zip");
    let count = le16(bytes, eocd + 10);
    let mut at = le32(bytes, eocd + 16);
    let locals = bytes[..at].to_vec();
    let mut records = Vec::new();
    for _ in 0..count {
        assert_eq!(&bytes[at..at + 4], b"PK\x01\x02");
        let len = 46 + le16(bytes, at + 28) + le16(bytes, at + 30) + le16(bytes, at + 32);
        records.push(bytes[at..at + len].to_vec());
        at += len;
    }
    (locals, records)
}

/// `locals`, then `records`, then an end record declaring exactly them.
fn assemble(locals: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let cd: Vec<u8> = records.concat();
    let mut out = locals.to_vec();
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    let n = u16::try_from(records.len()).unwrap().to_le_bytes();
    out.extend_from_slice(&n);
    out.extend_from_slice(&n);
    out.extend_from_slice(&u32::try_from(cd.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&u32::try_from(locals.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

const THREE: &[(&str, &[u8])] = &[
    ("a.txt", b"alpha"),
    ("b.txt", b"bravo"),
    ("c.txt", b"charlie"),
];

#[test]
fn a_piped_zip_whose_index_agrees_has_no_index_warnings() {
    for bytes in [
        fixture_zip(THREE),
        fixture_zip(&[]),
        // Names that repeat are a real, well-formed shape (ruling B3).
        fixture_zip_allowing_duplicates(&[("d.txt", b"one"), ("d.txt", b"two")]),
    ] {
        let (end, report) = walk_piped(&bytes);
        end.expect("a well-formed zip reads whole");
        assert_eq!(
            report.rung,
            Rung::ForwardOnly,
            "the access path is unchanged"
        );
        assert!(
            report.warnings.is_empty(),
            "the index was read and agrees, so nothing is lost: {:?}",
            report.warnings
        );
    }
}

/// zip 9 refuses a second entry of the same name, so the duplicate is spliced
/// in by hand: the first entry's local header and central record, twice,
/// with the second payload's bytes.
fn fixture_zip_allowing_duplicates(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut locals = Vec::new();
    let mut records = Vec::new();
    for (name, data) in entries {
        let (l, r) = split_zip(&fixture_zip(&[(*name, *data)]));
        let mut record = r[0].clone();
        record[42..46].copy_from_slice(&u32::try_from(locals.len()).unwrap().to_le_bytes());
        locals.extend_from_slice(&l);
        records.push(record);
    }
    assemble(&locals, &records)
}

#[test]
fn a_piped_zip_with_a_cut_central_directory_keeps_both_warnings() {
    let bytes = fixture_zip(THREE);
    let (locals, _) = split_zip(&bytes);
    let cut_inside = bytes[..locals.len() + 30].to_vec();
    let cut_in_the_end_record = bytes[..bytes.len() - 5].to_vec();
    for (what, cut) in [
        ("inside the central directory", cut_inside),
        ("inside the end record", cut_in_the_end_record),
        ("with no central directory at all", locals),
    ] {
        let (end, report) = walk_piped(&cut);
        let err = end.expect_err(what);
        assert_eq!(err.exit_code(), 5, "{what}: a cut is corruption: {err}");
        assert_eq!(
            index_warnings(&report),
            (true, true),
            "{what}: the index was not read, so both warnings stay as in 0.22.0: {:?}",
            report.warnings
        );
        assert!(disagreements(&report).is_empty(), "{what}");
    }
}

#[test]
fn a_piped_cloaked_name_is_reported() {
    let bytes = fixture_zip(THREE);
    let (mut locals, records) = split_zip(&bytes);
    // The first LOCAL name only: `a.txt` becomes `e.txt` on the pipe.
    assert_eq!(&locals[30..35], b"a.txt");
    locals[30] = b'e';
    let (end, report) = walk_piped(&assemble(&locals, &records));
    end.expect("a cloak is not damage");
    assert_eq!(disagreements(&report), vec![("e.txt".to_owned(), "name")]);
    assert_eq!(
        index_warnings(&report),
        (false, false),
        "the index was read; what it showed is the cloak warning"
    );
}

#[test]
fn a_piped_extra_local_entry_is_reported() {
    let bytes = fixture_zip(THREE);
    let (locals, mut records) = split_zip(&bytes);
    records.remove(1);
    let (end, report) = walk_piped(&assemble(&locals, &records));
    assert_eq!(end.expect("every local entry still reads"), 3);
    assert_eq!(
        disagreements(&report),
        vec![("b.txt".to_owned(), "entry count")]
    );

    // And the other way round: a central record no local header matches.
    let (locals, records) = split_zip(&bytes);
    let c_starts = le32(&records[2], 42);
    let (end, report) = walk_piped(&assemble(&locals[..c_starts], &records));
    end.expect("the walk itself is whole");
    assert_eq!(
        disagreements(&report),
        vec![("c.txt".to_owned(), "entry count")]
    );
}

#[test]
fn a_piped_reordered_index_is_reported() {
    let bytes = fixture_zip(THREE);
    let (locals, mut records) = split_zip(&bytes);
    records.swap(0, 2);
    let (end, report) = walk_piped(&assemble(&locals, &records));
    end.expect("order is not damage");
    assert_eq!(
        disagreements(&report),
        vec![("b.txt".to_owned(), "order")],
        "one warning for the archive, at the first pairing that runs backwards (c, then b)"
    );
}

#[test]
fn a_piped_field_disagreement_is_reported_as_on_the_seekable_path() {
    let bytes = fixture_zip(THREE);
    let (locals, mut records) = split_zip(&bytes);
    // The second central record's CRC-32.
    records[1][16] ^= 0xff;
    let (end, report) = walk_piped(&assemble(&locals, &records));
    end.expect("the local CRC-32 matches the payload");
    assert_eq!(disagreements(&report), vec![("b.txt".to_owned(), "CRC-32")]);
}

/// The end record declares a 2 GiB central directory. The forward walk never
/// sizes anything by that field: it walks the records by their own framing
/// (each variable field at most 65,535 bytes, read or skipped through a
/// fixed buffer) and only compares the declared size with what it walked. So
/// nothing proportional to the declaration is allocated, by construction.
/// The declaration contradicts the directory, so the index is not confirmed
/// and both warnings stay: the "fidelity warning" choice of ruling B2's
/// "over the bound", never a refusal and never exit 1.
#[test]
fn a_huge_declared_central_directory_on_a_pipe_is_bounded() {
    let mut bytes = fixture_zip(THREE);
    let eocd = bytes.len() - 22;
    bytes[eocd + 12..eocd + 16].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let (end, report) = walk_piped(&bytes);
    assert_eq!(end.expect("the entries themselves are whole"), 3);
    assert_eq!(
        index_warnings(&report),
        (true, true),
        "{:?}",
        report.warnings
    );
    assert!(disagreements(&report).is_empty());

    // The same through the binary: no refusal, no exit 1, and strict mode
    // still fails it.
    let out = run_piped(&["test", "-", "--strict-fidelity"], &bytes);
    assert_eq!(out.status.code(), Some(4), "{out:?}");
}

/// An end record whose records-on-this-disk count (bytes 8..10) disagrees
/// with its total (10..12) contradicts itself. A seekable read refuses it
/// (zip's own check, exit 5); the forward walk has already read every entry
/// by then, so it keeps going and does not confirm the index: both warnings
/// stay, strict mode fails it with 4, and nothing is exit 1.
#[test]
fn a_piped_end_record_whose_two_counts_disagree_keeps_both_warnings() {
    let mut bytes = fixture_zip(THREE);
    let eocd = bytes.len() - 22;
    assert_eq!(le16(&bytes, eocd + 10), 3, "the total");
    bytes[eocd + 8..eocd + 10].copy_from_slice(&2u16.to_le_bytes());
    let (end, report) = walk_piped(&bytes);
    assert_eq!(end.expect("the entries themselves are whole"), 3);
    assert_eq!(
        index_warnings(&report),
        (true, true),
        "{:?}",
        report.warnings
    );
    assert!(disagreements(&report).is_empty());

    let out = run_piped(&["test", "-", "--strict-fidelity"], &bytes);
    assert_eq!(out.status.code(), Some(4), "{out:?}");

    // The seekable path, for the contrast examples.txt states.
    let dir = scratch("eocd-counts");
    let path = write_temp_zip(&dir, &bytes);
    let out = run_on_path(&["test", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(5), "{out:?}");
}

/// The forward read delivers a symlink as a regular file holding its target;
/// only the central directory says it was a link. That stays a reported loss.
#[test]
fn a_piped_zip_holding_a_symlink_keeps_its_index_warnings() {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.add_symlink("link", "target", opts).expect("add_symlink");
        w.finish().expect("finish");
    }
    let (end, report) = walk_piped(&buf);
    end.expect("reads");
    assert_eq!(
        index_warnings(&report),
        (true, true),
        "{:?}",
        report.warnings
    );
}
