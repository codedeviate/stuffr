use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use tar::{Builder, Header};

pub(crate) const STUFFR: &str = env!("CARGO_BIN_EXE_stuffr");

/// A token unique to THIS test-binary run, mixed into every temp path below.
///
/// `{pid}-{something}` was NOT unique enough, and the failure it caused reads
/// exactly like a code defect. PIDs are reused within a day, and a later run
/// landing on a recycled PID inherited its predecessor's leftover directories
/// *with their contents in them* — so five unrelated tests failed with
/// "already exists" against 4436 leftovers, and deleting the leftovers turned
/// the gate green with no code change at all. A false red that costs a session.
///
/// `RandomState` is the dependency-free source of per-process randomness in
/// `std`: its hasher keys are seeded from the OS, so two concurrent or
/// consecutive runs cannot agree on this token however their PIDs land. That
/// keeps the name collision-proof rather than merely unlikely. The scratch
/// guard below is the other half: it removes its directory on drop, so a
/// failing (panicking) test no longer leaves its files behind either; only a
/// crashed or interrupted run can, and the token keeps those harmless.
pub(crate) static RUN_TOKEN: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use std::hash::{BuildHasher, Hasher};
    let n = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{}-{n:016x}", std::process::id())
});

/// A scratch path that removes itself, file or directory tree, when dropped.
///
/// Drop runs while a panicking test unwinds, so a failing test no longer
/// leaves its files behind; only a crashed or interrupted run can, and the
/// `RUN_TOKEN` in the name keeps those harmless. The path is NOT created (a
/// test may make it a file or a directory, or check that it does not exist),
/// and a test's `tmp("a")` and `tmp("a.gz")` still share one parent, which
/// several tests rely on (`unpack a.gz` writes `a` beside it). It derefs to
/// `Path`.
///
/// `tempfile::TempDir` was tried first and does not fit: it creates its
/// directory up front, and each call gets a different parent.
pub(crate) struct Scratch(PathBuf);

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

impl AsRef<std::ffi::OsStr> for Scratch {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A symlink is removed as a file, never followed.
        match std::fs::symlink_metadata(&self.0) {
            Ok(m) if m.is_dir() => {
                make_dirs_writable(&self.0);
                let _ = std::fs::remove_dir_all(&self.0);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&self.0);
            }
            Err(_) => {}
        }
    }
}

/// Restores user rwx on every directory under `p` (never following symlinks),
/// so a test that panics while a directory is read-only still cleans up.
// keep in sync with the copies in tests/cli/common.rs, compat_harness/mod.rs (stuffr-cli),
// src/compat/compress/test_scratch.rs (stuffr-cli), tests/zip_on_a_pipe.rs (stuffr-formats),
// tests/common/mod.rs and src/entries.rs (stuffr)
#[cfg(unix)]
pub(crate) fn make_dirs_writable(p: &Path) {
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
pub(crate) fn make_dirs_writable(_p: &Path) {}

pub(crate) fn tmp(name: &str) -> Scratch {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-{}-{name}", *RUN_TOKEN));
    Scratch(p)
}

/// Runs `stuffr info -` over `bytes` and returns its stdout.
pub(crate) fn info_over_stdin(bytes: &[u8]) -> String {
    let mut child = Command::new(STUFFR)
        .args(["info", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "stuffr info - must succeed");
    String::from_utf8(out.stdout).unwrap()
}

pub(crate) static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory for one test. Real files on disk, not just
/// bytes in memory, so `list_names_every_entry_and_extracts_nothing` can
/// assert the filesystem is untouched afterwards.
///
/// Named from [`RUN_TOKEN`] rather than `{pid}-{counter}`, and the word
/// "fresh" in the sentence above is why — see that constant for the false red
/// the old name produced. `create_dir_all` is deliberately kept (rather than
/// `create_dir`, which would refuse an existing path): with a random token the
/// path cannot pre-exist, so a refusal would only ever fire on a genuine
/// filesystem fault and `create_dir_all` reports that just as loudly.
pub(crate) fn tmp_dir() -> Scratch {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-archive-{}-{n}", *RUN_TOKEN));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    Scratch(p)
}

/// Writes a GNU-format tar header for `name`/`data` into `builder`. Kept
/// separate from callers so every fixture builder below sets exactly the
/// same fields the same way.
pub(crate) fn append_tar_entry<W: Write>(builder: &mut Builder<W>, name: &str, data: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    // `append_data` sets the path and recomputes the checksum itself, in
    // that order — see `tar::Builder::append_data`'s own source.
    builder.append_data(&mut header, name, data).unwrap();
}

/// A real tar archive, written to `dir/fixture.tar`.
pub(crate) fn write_fixture_tar(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let path = dir.join("fixture.tar");
    let mut builder = Builder::new(std::fs::File::create(&path).unwrap());
    for (name, data) in entries {
        append_tar_entry(&mut builder, name, data);
    }
    builder.finish().unwrap();
    path
}

/// The same tar bytes, real-gzip-wrapped (via `flate2`) under `name` —
/// `"fixture.tar.gz"` or `"fixture.tgz"` — exercising the exact shapes
/// `resolve_chain_deep` must resolve as "tar over gzip".
pub(crate) fn write_fixture_tar_gz(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        for (n, data) in entries {
            append_tar_entry(&mut builder, n, data);
        }
        builder.finish().unwrap();
    }
    let path = dir.join(name);
    let mut enc = GzEncoder::new(
        std::fs::File::create(&path).unwrap(),
        Compression::default(),
    );
    enc.write_all(&tar_bytes).unwrap();
    enc.finish().unwrap();
    path
}

/// Gzip-wraps arbitrary bytes once — used to build a nesting-depth bomb.
pub(crate) fn gzip_wrap(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// Truncates `good` to half its length: a real, structural corruption (a
/// missing or partial end-of-archive marker), not a bit flip tar has no way
/// to detect at all — it carries no payload checksum.
pub(crate) fn corrupt_midway(good: &Path) -> PathBuf {
    let bytes = std::fs::read(good).unwrap();
    let cut = bytes.len() / 2;
    let corrupt = good.with_file_name("corrupt.tar");
    std::fs::write(&corrupt, &bytes[..cut]).unwrap();
    corrupt
}

pub(crate) fn run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(STUFFR).args(args).status().unwrap()
}

pub(crate) fn run_output(args: &[&str]) -> std::process::Output {
    Command::new(STUFFR).args(args).output().unwrap()
}

/// Runs stuffr in `dir` (its working directory) with `TZ=UTC`, so a date
/// `stuffr ls` prints in local time is fixed text in a test.
pub(crate) fn run_in_dir_output(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(STUFFR)
        .args(args)
        .current_dir(dir)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

pub(crate) fn run_with_stdin_output(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(STUFFR)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A child that exits without reading its stdin closes the pipe; EPIPE is fine.
    match child.stdin.take().unwrap().write_all(input) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        r => r.unwrap(),
    }
    child.wait_with_output().unwrap()
}

/// The streaming premise applied to `list`/`test`: stdin, no seek.
pub(crate) fn run_with_stdin(args: &[&str], input: &[u8]) -> String {
    let out = run_with_stdin_output(args, input);
    String::from_utf8(out.stdout).unwrap()
}

/// A stored zip holding one symlink entry (`S_IFLNK` in the central
/// directory's external attributes) whose target payload is `target_len`
/// bytes. Hand-built, so the size fields are exactly what the test says.
pub(crate) fn zip_with_one_symlink(name: &str, target_len: usize) -> Vec<u8> {
    let target = vec![b't'; target_len];
    let crc = {
        let mut c = 0xFFFF_FFFFu32;
        for &b in &target {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    };
    let size = target_len as u32;
    let mut z = Vec::new();
    // Local file header.
    z.extend_from_slice(b"PK\x03\x04");
    z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]); // ver, flags, stored, time, date
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(&target);
    let cd_offset = z.len() as u32;
    // Central directory record.
    z.extend_from_slice(b"PK\x01\x02");
    z.extend_from_slice(&[0x14, 0x03, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]); // made by unix
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attrs
    z.extend_from_slice(&(0o120_777u32 << 16).to_le_bytes());
    z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    z.extend_from_slice(name.as_bytes());
    let cd_len = z.len() as u32 - cd_offset;
    // End of central directory.
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend_from_slice(&cd_len.to_le_bytes());
    z.extend_from_slice(&cd_offset.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// A small `.tar.gz` whose single all-zero entry gzip crushes hard — real
/// enough to measure, not assumed. Same 2 MiB size `a_bomb_exits_six_and_
/// leaves_no_partial_output` uses for the bare-codec case.
pub(crate) fn write_bomb_tar_gz(dir: &Path) -> PathBuf {
    write_fixture_tar_gz(
        dir,
        "bomb.tar.gz",
        &[("bomb.bin", &vec![0u8; 2 * 1024 * 1024])],
    )
}

/// The mtime every raw fixture entry carries, so a test can assert that
/// extraction put it back rather than that it happens to be "recent".
pub(crate) const FIXTURE_MTIME: u64 = 1_600_000_000;

/// A tar entry whose name is written straight into the 100-byte header field,
/// bypassing every validation `Builder::append_data`/`Header::set_path` would
/// apply. `write_fixture_tar` cannot express these names at all.
pub(crate) fn raw_header(
    name: &str,
    kind: tar::EntryType,
    link_target: Option<&str>,
    size: u64,
    mode: u32,
) -> Header {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_mtime(FIXTURE_MTIME);
    header.set_entry_type(kind);
    {
        let gnu = header.as_gnu_mut().expect("new_gnu is a GNU header");
        let bytes = name.as_bytes();
        assert!(
            bytes.len() <= gnu.name.len(),
            "raw fixture names must fit tar's 100-byte name field"
        );
        gnu.name[..bytes.len()].copy_from_slice(bytes);
        if let Some(target) = link_target {
            let bytes = target.as_bytes();
            assert!(
                bytes.len() <= gnu.linkname.len(),
                "raw fixture link targets must fit tar's 100-byte linkname field"
            );
            gnu.linkname[..bytes.len()].copy_from_slice(bytes);
        }
    }
    header.set_cksum();
    header
}

/// One raw entry, described the way the fixtures below need it.
pub(crate) enum Raw<'a> {
    File(&'a str, &'a [u8]),
    /// A file carrying an explicit mode, for the metadata tests.
    ModedFile(&'a str, &'a [u8], u32),
    Dir(&'a str),
    Symlink(&'a str, &'a str),
    /// A hard link entry: name, then the target it links to.
    Hardlink(&'a str, &'a str),
    /// A named pipe: `EntryKind::Other`, which has no shape on disk here.
    Fifo(&'a str),
}

/// Writes an archive whose entry names have passed through no validation at
/// all — the shape stuffr must be able to refuse.
pub(crate) fn write_raw_tar(path: &Path, entries: &[Raw<'_>]) -> PathBuf {
    let mut builder = Builder::new(std::fs::File::create(path).unwrap());
    for entry in entries {
        match entry {
            Raw::File(name, data) => {
                let header = raw_header(
                    name,
                    tar::EntryType::Regular,
                    None,
                    data.len() as u64,
                    0o644,
                );
                builder.append(&header, *data).unwrap();
            }
            Raw::ModedFile(name, data, mode) => {
                let header = raw_header(
                    name,
                    tar::EntryType::Regular,
                    None,
                    data.len() as u64,
                    *mode,
                );
                builder.append(&header, *data).unwrap();
            }
            Raw::Dir(name) => {
                let header = raw_header(name, tar::EntryType::Directory, None, 0, 0o755);
                builder.append(&header, std::io::empty()).unwrap();
            }
            Raw::Symlink(name, target) => {
                let header = raw_header(name, tar::EntryType::Symlink, Some(target), 0, 0o777);
                builder.append(&header, std::io::empty()).unwrap();
            }
            Raw::Hardlink(name, target) => {
                let header = raw_header(name, tar::EntryType::Link, Some(target), 0, 0o644);
                builder.append(&header, std::io::empty()).unwrap();
            }
            Raw::Fifo(name) => {
                let header = raw_header(name, tar::EntryType::Fifo, None, 0, 0o644);
                builder.append(&header, std::io::empty()).unwrap();
            }
        }
    }
    builder.finish().unwrap();
    path.to_path_buf()
}

/// One LHA level-1 header plus a stored (`-lh0-`) payload and the
/// end-of-archive marker, built here rather than through stuffr for the same
/// reason `write_raw_tar` exists: these are archives stuffr must be able to
/// REFUSE, and it would never write one.
pub(crate) fn raw_lha_entry(name: &[u8], method: &[u8; 5], content: &[u8]) -> Vec<u8> {
    let mut crc: u16 = 0;
    for &b in content {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    let size = content.len() as u32;
    let mut counted: Vec<u8> = Vec::new();
    counted.extend_from_slice(method);
    counted.extend_from_slice(&size.to_le_bytes()); // level-1 skip size
    counted.extend_from_slice(&size.to_le_bytes()); // original size
    counted.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    counted.push(0x20); // MS-DOS ARCHIVE
    counted.push(1); // header level
    counted.push(name.len() as u8);
    counted.extend_from_slice(name);
    counted.extend_from_slice(&crc.to_le_bytes());
    counted.push(b'U'); // OS-TYPE: Unix
    counted.extend_from_slice(&0u16.to_le_bytes()); // no extra headers

    let mut out = vec![
        counted.len() as u8,
        counted.iter().fold(0u8, |a, &b| a.wrapping_add(b)),
    ];
    out.extend_from_slice(&counted);
    out.extend_from_slice(content);
    out.push(0); // end-of-archive marker
    out
}

/// GNU tar, wherever this platform keeps it: `gtar` (Homebrew's `gnu-tar`
/// on macOS) or the platform `tar` when `--version` says it is GNU's, as on
/// Linux. Missing is a failure naming the fix, never a fallback to bsdtar —
/// which rejects GNU-only flags such as `--hole-detection` and would fail as
/// an unexplained "reference tool failed". `tar.rs`'s `gnu_tar()`'s check.
pub(crate) fn require_gnu_tar() -> PathBuf {
    if let Some(gtar) = which("gtar") {
        return gtar;
    }
    let tar = require_bin("tar");
    let out = Command::new(&tar).arg("--version").output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("GNU tar"),
        "no GNU tar: neither `gtar` nor a GNU `tar` on PATH (macOS: `brew install gnu-tar`)"
    );
    tar
}

/// `tar.rs`'s own tests gate on the system tool the same way rather than
/// failing a machine that has none.
pub(crate) fn which_tar() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("tar"))
        .find(|candidate| candidate.is_file())
}

#[cfg(unix)]
pub(crate) fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

pub(crate) fn mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Builds a `.tar.lz` and returns `(legitimate, crafted)`.
///
/// `crafted` differs from `legitimate` in exactly ONE byte: lzip's header
/// byte 5, the coded dictionary size, forced to `0x1D` — 512 MiB. The
/// payload is untouched and still decodes, so anything the crafted file
/// costs comes purely from the DECLARATION, which is what makes it the
/// right probe for a pre-output allocation guard. The third element is the
/// directory guard; the caller keeps it alive for as long as it uses the paths.
pub(crate) fn craft_a_tar_lz_declaring_a_huge_dictionary(tag: &str) -> (PathBuf, PathBuf, Scratch) {
    let dir = tmp(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let tar_path = dir.join("bundle.tar");
    write_raw_tar(
        &tar_path,
        &[Raw::File("a.txt", b"hello from inside the tar")],
    );

    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                tar_path.to_str().unwrap(),
                "--format",
                "lzip",
                "--force"
            ])
            .status()
            .unwrap()
            .success(),
        "packing the fixture must succeed"
    );
    let legit = dir.join("bundle.tar.lz");

    let mut bytes = std::fs::read(&legit).unwrap();
    assert_eq!(&bytes[..4], b"LZIP", "fixture must really be lzip");
    // Byte 5 is lzip's coded dictionary size. 0x1D asks for 512 MiB.
    bytes[5] = 0x1D;
    let crafted = dir.join("crafted.tar.lz");
    std::fs::write(&crafted, &bytes).unwrap();

    (legit, crafted, dir)
}

/// Locates `bin` on `PATH`.
///
/// A local copy rather than a shared helper, matching this tree's existing
/// convention: `ar.rs`, `cpio.rs`, `zip.rs` and `zip_on_a_pipe.rs` each carry
/// their own. That four-copy situation was examined in Phase 2 and accepted
/// deliberately; extracting a shared test helper is a tree-wide refactor, not
/// something to smuggle into a testing task.
pub(crate) fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

/// Locates `bin` on `PATH`, panicking rather than silently skipping if it is
/// absent. CI installs every tool named here (`tar` and `ar` ship with the
/// image; `.github/workflows/ci.yml` installs `cpio`, `zip` and `unzip` on all
/// three test jobs), so an absence means only a contributor's own machine
/// lacks it — and a silent `return` would report a cross-implementation test
/// as PASSING having verified nothing at all.
pub(crate) fn require_bin(bin: &str) -> PathBuf {
    which(bin).unwrap_or_else(|| {
        panic!(
            "no reference `{bin}` tool found on PATH — this test proved nothing, which is \
             worth knowing rather than passing silently"
        )
    })
}

/// lhasa, under EITHER of the two names its packagers give it: Homebrew
/// installs the binary as `lha`, Debian and Ubuntu install exactly one
/// binary and call it `lhasa`. Same program, different spelling, so a
/// `require_bin("lha")` here would pass on a developer's Mac and turn all
/// three CI test jobs red. `legacy/lha.rs`'s own `require_lhasa` carries the
/// evidence (package file lists, both distributions) and is the same
/// resolution; the duplication is the same one `require_bin` itself already
/// has between this file and four format modules.
pub(crate) fn require_lhasa() -> PathBuf {
    which("lha").or_else(|| which("lhasa")).unwrap_or_else(|| {
        panic!(
            "no reference lhasa tool found on PATH under either of its two names, `lha` \
             (Homebrew) or `lhasa` (Debian/Ubuntu) — this test proved nothing, which is worth \
             knowing rather than passing silently"
        )
    })
}

/// lhasa's banner, which carries its VERSION, so an assertion that fires on
/// a runner says which build produced it. Ubuntu noble ships lhasa 0.4.0
/// while this project's `-lhd-` guard was measured against 0.6.0 — see
/// `legacy/lha.rs`'s `lhasa_banner` for why that difference is worth one
/// line of output.
pub(crate) fn lhasa_banner(bin: &std::path::Path) -> String {
    let out = Command::new(bin)
        .output()
        .expect("run lhasa with no arguments for its banner");
    let text = if out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    text.lines().next().unwrap_or("<no banner>").to_string()
}

/// The permission bits only. The file-type bits are not what any container
/// carries in its mode field, and comparing them would fail on the kind rather
/// than on the permissions.
#[cfg(unix)]
pub(crate) fn perm_bits(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

/// A tree fixture whose every distinguishable fact is one a container is
/// expected to carry: a nested directory, an EMPTY directory (which only a
/// directory entry can preserve), a symlink, and two files with DIFFERENT
/// modes.
///
/// Every mode is `0o600`/`0o700` deliberately: extraction tools mask restored
/// permissions with the process umask, so a fixture using `0o644`/`0o755`
/// compares equal under umask 022 and unequal under umask 077. These two have
/// no bits any umask can clear, which makes the comparison umask-independent
/// rather than passing on this machine's umask alone.
#[cfg(unix)]
pub(crate) fn build_reference_tree(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    std::fs::write(root.join("sub/b.bin"), b"\x00\xff\x00beta").unwrap();
    std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
    for (p, mode) in [
        (root.to_path_buf(), 0o700),
        (root.join("sub"), 0o700),
        (root.join("empty"), 0o700),
        (root.join("a.txt"), 0o600),
        (root.join("sub/b.bin"), 0o600),
    ] {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Everything under `root`, relative, sorted: name, kind, mode, and the file's
/// own bytes or the link's own target.
///
/// NOT just names — the whole point of the cross-implementation property is
/// that two tools agree about the CONTENTS of a tree, and a comparison of
/// names alone passes against an extractor that produced empty files with the
/// wrong modes.
///
/// A symlink's mode is deliberately omitted: `std` cannot restore one (no
/// `lchmod`), which is the same limitation `README.md` records for mtime, and
/// every tool here leaves it at the platform default.
#[cfg(unix)]
pub(crate) fn tree_snapshot(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            let md = std::fs::symlink_metadata(&path).unwrap();
            if md.is_symlink() {
                out.push(format!(
                    "{rel}: symlink -> {}",
                    std::fs::read_link(&path).unwrap().display()
                ));
            } else if md.is_dir() {
                out.push(format!("{rel}: dir mode {:o}", perm_bits(&md)));
                stack.push(path);
            } else {
                out.push(format!(
                    "{rel}: file mode {:o} bytes {:?}",
                    perm_bits(&md),
                    std::fs::read(&path).unwrap()
                ));
            }
        }
    }
    out.sort();
    out
}

/// Runs a reference tool, with `COPYFILE_DISABLE=1` set unconditionally.
///
/// That variable is macOS's: bsdtar stores every file's extended attributes as
/// a companion `._name` AppleDouble entry, and macOS puts a
/// `com.apple.provenance` xattr on ordinary files, so a tree written by the
/// system tar comes back with a `._` sibling for every entry and the
/// comparison below fails for a reason that has nothing to do with stuffr.
/// Linux's tar ignores the variable, so setting it always costs nothing and
/// keeps the two platforms running the same command.
pub(crate) fn run_tool(bin: &Path, args: &[&std::ffi::OsStr], cwd: &Path, stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("COPYFILE_DISABLE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "reference tool {} {:?} failed: {}",
        bin.display(),
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `OsStr` borrow, so `run_tool`'s argument list can mix `&str` and `&Path`.
pub(crate) fn os(s: &impl AsRef<std::ffi::OsStr>) -> &std::ffi::OsStr {
    s.as_ref()
}

pub(crate) fn pack_ok(args: &[&std::ffi::OsStr]) -> String {
    let out = Command::new(STUFFR)
        .arg("pack")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stuffr pack {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).to_string()
}

pub(crate) fn unpack_ok(archive: &Path, dest: &Path) {
    let out = Command::new(STUFFR)
        .args([
            std::ffi::OsStr::new("unpack"),
            archive.as_ref(),
            std::ffi::OsStr::new("-C"),
            dest.as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stuffr unpack {} failed: {}",
        archive.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Every `.rs` file under the workspace's `crates/*/src/`.
///
/// Discovered by walking, not listed: a message added by a future task in a
/// file that does not exist yet is exactly the case the hardcoded version of
/// this guard could not cover.
///
/// `CARGO_MANIFEST_DIR` bakes an absolute path at compile time, the same
/// hazard `CARGO_BIN_EXE_stuffr` already carries at the top of this file — if
/// the repository is moved, `cargo clean -p stuffr-cli` is the fix for both
/// (see `CLAUDE.md`).
pub(crate) fn workspace_source_files() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = std::fs::read_dir(crates)
        .unwrap()
        .map(|e| e.unwrap().path().join("src"))
        .filter(|p| p.is_dir())
        .collect();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Every Rust string literal in `src`, as the compiler will see it: `\` at
/// end of line strips the newline AND the next line's leading whitespace, so a
/// literal written with that continuation contains no indentation at all,
/// while one that lost its `\` carries the indentation into the message.
///
/// Comments, char literals and lifetimes are skipped so that a `"` inside one
/// cannot desynchronise the scan. Raw strings are included: they cannot use
/// `\`-continuation, so a multi-line one carries its indentation too.
pub(crate) fn rust_string_literals(src: &str) -> Vec<(usize, String)> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < c.len() {
        if c[i] == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            i += 2;
            while i < c.len() && depth > 0 {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if c[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            continue;
        }
        // A char literal (`'a'`, `'\''`, `'"'`) or a lifetime (`'a`). Telling
        // them apart matters: treating `'"'` as a lifetime would leave the
        // scan inside a string it never entered.
        if c[i] == '\'' {
            if c.get(i + 1) == Some(&'\\') {
                let mut j = i + 2;
                while j < c.len() && c[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            if c.get(i + 2) == Some(&'\'') {
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        // A raw string, optionally byte: `r"…"`, `r#"…"#`, `br##"…"##`.
        let ident_before = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
        if (c[i] == 'r' || c[i] == 'b') && !ident_before {
            let mut j = i;
            if c[j] == 'b' {
                j += 1;
            }
            if c.get(j) == Some(&'r') {
                j += 1;
                let mut hashes = 0usize;
                while c.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if c.get(j) == Some(&'"') {
                    let start_line = line;
                    j += 1;
                    let mut text = String::new();
                    loop {
                        if j >= c.len() {
                            break;
                        }
                        if c[j] == '"' && c[j + 1..].iter().take(hashes).all(|h| *h == '#') {
                            j += 1 + hashes;
                            break;
                        }
                        if c[j] == '\n' {
                            line += 1;
                        }
                        text.push(c[j]);
                        j += 1;
                    }
                    out.push((start_line, text));
                    i = j;
                    continue;
                }
            }
        }
        if c[i] == '"' {
            let start_line = line;
            let mut text = String::new();
            let mut j = i + 1;
            while j < c.len() && c[j] != '"' {
                if c[j] == '\\' && c.get(j + 1) == Some(&'\n') {
                    // The continuation rustc applies, and the whole reason a
                    // correctly-written message carries no indentation.
                    line += 1;
                    j += 2;
                    while matches!(c.get(j), Some(' ' | '\t' | '\r' | '\n')) {
                        if c[j] == '\n' {
                            line += 1;
                        }
                        j += 1;
                    }
                    continue;
                }
                if c[j] == '\\' {
                    text.push(c[j]);
                    if let Some(&e) = c.get(j + 1) {
                        text.push(e);
                    }
                    j += 2;
                    continue;
                }
                if c[j] == '\n' {
                    line += 1;
                }
                text.push(c[j]);
                j += 1;
            }
            out.push((start_line, text));
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// The byte offset of the first run of three or more spaces in `text`, if any.
pub(crate) fn first_space_run(text: &str) -> Option<usize> {
    text.as_bytes().windows(3).position(|w| w == b"   ")
}

/// Whether a run of spaces is a deliberate COLUMN, not a collapsed
/// continuation: everything before it on its own line is a ONE-WORD label
/// ending in a colon, which is `stuffr info`'s output shape (`format:   gzip`)
/// and the `/proc/meminfo` fixture's (`MemAvailable:    1048576 kB`).
///
/// Anything else — the historical defect's `` (`-o bundle.tar`, `` — is prose,
/// and prose never needs three spaces in a row.
///
/// The single-word rule is load-bearing, not tidiness. An earlier version
/// allowed any label of alphanumerics and SPACES, which exempted a whole prose
/// clause that happened to end in a colon —
/// `"stuffr cannot do this:                    try force"` passed it — and
/// messages in this tree routinely end a clause with a colon before a list.
/// One word still admits all seven exemptions the workspace actually has
/// (`format:`, `chain:`, `rung:`, `size:` twice, `memory:`, `MemTotal:`).
pub(crate) fn is_column_label(prefix: &str) -> bool {
    let tail = prefix
        .rsplit('\n')
        .next()
        .unwrap_or(prefix)
        .rsplit("\\n")
        .next()
        .unwrap_or(prefix);
    match tail.strip_suffix(':') {
        Some(label) => {
            !label.is_empty()
                && !label.contains(' ')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        }
        None => false,
    }
}

/// Whether `path` is a compatibility family's message table,
/// `src/compat/<family>/messages.rs`, matched by whole path components.
///
/// Those files hold another tool's text copied verbatim (bzip2.c's licence
/// and usage indent with three spaces), and the differential harness pins
/// every byte of it against the real tool, so a "collapsed" run there is the
/// reference's own layout, not a defect. Nothing else is exempt.
pub(crate) fn is_verbatim_reference_messages(path: &std::path::Path) -> bool {
    let parts: Vec<&std::ffi::OsStr> = path.components().map(|c| c.as_os_str()).collect();
    // `src/compat/<family>/messages.rs`, or a family with one personality
    // per reference: `src/compat/<family>/<flavour>/messages.rs` (gzip's
    // `gnu` and `bsd`, compress's `apple` and `ncompress`).
    matches!(
        parts.as_slice(),
        [.., src, compat, _family, file]
            if *src == "src" && *compat == "compat" && *file == "messages.rs"
    ) || matches!(
        parts.as_slice(),
        [.., src, compat, _family, _flavour, file]
            if *src == "src" && *compat == "compat" && *file == "messages.rs"
    )
}

/// Builds a zip through `stuffr pack` itself. There is no `zip` dev-dependency
/// here (unlike `tar`/`flate2`), and for these tests that is fine: the point
/// is not to validate stuffr's zip WRITER but to have an archive whose
/// container carries a real central directory, which is what puts `--index`
/// on its random-access route.
pub(crate) fn write_zip_via_pack(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let mut paths = Vec::new();
    for (name, data) in entries {
        let p = src.join(name);
        std::fs::write(&p, data).unwrap();
        paths.push(p);
    }
    let zip = dir.join("bundle.zip");
    let mut args: Vec<String> = vec!["pack".into()];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    args.push("-o".into());
    args.push(zip.to_string_lossy().into_owned());
    let out = Command::new(STUFFR).args(&args).output().unwrap();
    assert!(
        out.status.success(),
        "building the zip fixture failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    zip
}

/// `bytes`, a zip, with the last byte of its FIRST local header's name
/// changed and its central record left alone: a "cloaked" zip. Since ruling
/// B2 this is the shape a piped zip read really does warn about (a
/// `HeadersDisagree` on `name`): a well-formed piped zip no longer warns.
pub(crate) fn cloak_first_local_name(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    assert_eq!(
        &out[..4],
        b"PK\x03\x04",
        "a zip that opens with a local header"
    );
    let name_len = usize::from(u16::from_le_bytes([out[26], out[27]]));
    out[30 + name_len - 1] ^= 0x20;
    out
}

/// **The documents this crate's count guards scan, in one place.**
///
/// It was three — this crate's README, the workspace README and
/// `examples.txt` — and that list is precisely what let Phase 3c's final
/// review find two stale published claims by hand: `crates/stuffr/README.md`
/// is a live crates.io landing page that did not know the legacy formats
/// existed, and `CONTRIBUTING.md` still said "eleven codecs". Neither was in
/// the list, so neither could have been caught. Every follow-up that review
/// raised lived in a file no task owned, which is the argument for widening
/// the scan rather than adding a checklist.
///
/// All four crate READMEs are here because all four are published pages, and
/// `CONTRIBUTING.md` because it is the document a contributor works from.
pub(crate) fn user_facing_documents() -> Vec<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    vec![
        manifest_dir.join("README.md"),
        manifest_dir.join("src").join("examples.txt"),
        root.join("README.md"),
        root.join("CONTRIBUTING.md"),
        root.join("crates").join("stuffr").join("README.md"),
        root.join("crates").join("stuffr-core").join("README.md"),
        root.join("crates").join("stuffr-formats").join("README.md"),
    ]
}

/// CRC-32 (IEEE 802.3 — the same polynomial zip's own local/central headers
/// use), bit-by-bit. No crate needed for six known-plaintext payloads, and
/// pulling in a dependency for this one computation would be a heavier fix
/// than the six lines below.
pub(crate) fn salvage_fixture_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// One Stored local file header plus its payload, and the offset it was
/// written at (needed to build the central-directory record alongside it).
pub(crate) struct SalvageFixtureLocalRecord {
    pub(crate) offset: u32,
    pub(crate) name: &'static str,
    pub(crate) crc: u32,
    pub(crate) len: u32,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn salvage_fixture_local_record(
    offset: u32,
    name: &'static str,
    payload: &'static [u8],
) -> SalvageFixtureLocalRecord {
    let crc = salvage_fixture_crc32(payload);
    let len = u32::try_from(payload.len()).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]); // local file header signature
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed to extract
    bytes.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // compression method: Stored
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    bytes.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes()); // compressed size
    bytes.extend_from_slice(&len.to_le_bytes()); // uncompressed size
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(payload);
    SalvageFixtureLocalRecord {
        offset,
        name,
        crc,
        len,
        bytes,
    }
}

pub(crate) fn salvage_fixture_central_record(rec: &SalvageFixtureLocalRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]); // central header signature
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version made by
    bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed to extract
    bytes.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // compression method: Stored
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    bytes.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
    bytes.extend_from_slice(&rec.crc.to_le_bytes());
    bytes.extend_from_slice(&rec.len.to_le_bytes()); // compressed size
    bytes.extend_from_slice(&rec.len.to_le_bytes()); // uncompressed size
    bytes.extend_from_slice(&u16::try_from(rec.name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    bytes.extend_from_slice(&0u16.to_le_bytes()); // comment length
    bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    bytes.extend_from_slice(&0u16.to_le_bytes()); // internal file attrs
    bytes.extend_from_slice(&0u32.to_le_bytes()); // external file attrs
    bytes.extend_from_slice(&rec.offset.to_le_bytes()); // local header offset
    bytes.extend_from_slice(rec.name.as_bytes());
    bytes
}

/// What the two duplicate records at scan positions 6 and 7 carry.
///
/// [`build_shadowing_zip_fixture`]'s duplicates are byte-for-byte copies —
/// the shape the motivating real-world archive had, and the only shape this
/// file's fixtures modelled until the final whole-branch review. Under it,
/// annotating a duplicate costs nothing to get right and overwriting one on
/// disk costs nothing at all, because the bytes agree; three separate
/// findings hid behind exactly that. [`build_duplicate_name_zip_fixture`]
/// is the other half, and both are kept, because both are real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SalvageFixtureDuplicates {
    /// A byte-for-byte copy of the record whose name it repeats.
    Identical,
    /// The same name and the same length, DIFFERENT bytes — so both
    /// records still verify as `Intact`, and recovering one and then
    /// overwriting it with the other genuinely loses data.
    Distinct,
}

/// Builds the shadowing fixture this section's own doc comment describes:
/// 6 names, 8 physical local records, a central directory declaring all 8.
pub(crate) fn build_shadowing_zip_fixture() -> Vec<u8> {
    build_duplicating_zip_fixture(SalvageFixtureDuplicates::Identical)
}

/// The realistic counterpart: the same eight records under the same six
/// names, with each duplicate carrying a DIFFERENT, same-length payload and
/// its own recomputed CRC-32.
///
/// Same length on purpose — every size field in both headers stays valid, so
/// the payload bytes and the checksum over them are the ONLY difference
/// between this fixture and [`build_shadowing_zip_fixture`]. Anything that
/// behaves differently between the two does so because the duplicate's
/// content differs, and for no other reason.
pub(crate) fn build_duplicate_name_zip_fixture() -> Vec<u8> {
    build_duplicating_zip_fixture(SalvageFixtureDuplicates::Distinct)
}

pub(crate) fn build_duplicating_zip_fixture(duplicates: SalvageFixtureDuplicates) -> Vec<u8> {
    let originals_src: [(&str, &[u8]); 6] = [
        ("one.txt", b"payload for entry one"),
        ("two.txt", b"payload for entry two"),
        (
            "shadowed-a.bin",
            b"payload for the first record that will be shadowed",
        ),
        (
            "shadowed-b.bin",
            b"payload for the second record that will be shadowed",
        ),
        ("five.txt", b"payload for entry five"),
        ("six.txt", b"payload for entry six"),
    ];

    let mut out = Vec::new();
    let mut originals = Vec::new();
    for (name, payload) in originals_src {
        let rec = salvage_fixture_local_record(u32::try_from(out.len()).unwrap(), name, payload);
        out.extend_from_slice(&rec.bytes);
        originals.push(rec);
    }

    // The two physical duplicates, appended AFTER every original local
    // record — this is what puts their scan positions at 6 and 7. Under
    // `Distinct` their payloads are replaced by same-length, different
    // strings; `salvage_fixture_local_record` recomputes the CRC-32 from
    // whatever payload it is handed, so both the local header's copy and
    // (via `salvage_fixture_central_record`) the central directory's copy
    // follow automatically.
    const DIFFERENT_A: &[u8] = b"DIFFERENT bytes under the first duplicated name!!!";
    const DIFFERENT_B: &[u8] = b"DIFFERENT bytes under the second duplicated name!!!";
    let (payload_a, payload_b) = match duplicates {
        SalvageFixtureDuplicates::Identical => (originals_src[2].1, originals_src[3].1),
        SalvageFixtureDuplicates::Distinct => {
            // Length-preserving is asserted, not eyeballed: a mismatch would
            // make the fixture itself the damage rather than the repeated
            // name it exists to model.
            assert_eq!(originals_src[2].1.len(), DIFFERENT_A.len());
            assert_eq!(originals_src[3].1.len(), DIFFERENT_B.len());
            (DIFFERENT_A, DIFFERENT_B)
        }
    };
    let dup_a = salvage_fixture_local_record(
        u32::try_from(out.len()).unwrap(),
        "shadowed-a.bin",
        payload_a,
    );
    out.extend_from_slice(&dup_a.bytes);
    let dup_b = salvage_fixture_local_record(
        u32::try_from(out.len()).unwrap(),
        "shadowed-b.bin",
        payload_b,
    );
    out.extend_from_slice(&dup_b.bytes);

    let cd_start = u32::try_from(out.len()).unwrap();
    for rec in &originals {
        out.extend_from_slice(&salvage_fixture_central_record(rec));
    }
    out.extend_from_slice(&salvage_fixture_central_record(&dup_a));
    out.extend_from_slice(&salvage_fixture_central_record(&dup_b));
    let cd_size = u32::try_from(out.len()).unwrap() - cd_start;

    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]); // end of central directory signature
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with the start of the cd
    out.extend_from_slice(&8u16.to_le_bytes()); // cd records on this disk
    out.extend_from_slice(&8u16.to_le_bytes()); // cd records total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    out
}

pub(crate) fn write_shadowing_zip_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("shadowing.zip");
    std::fs::write(&path, build_shadowing_zip_fixture()).unwrap();
    path
}

pub(crate) fn write_duplicate_name_zip_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("duplicate-names.zip");
    std::fs::write(&path, build_duplicate_name_zip_fixture()).unwrap();
    path
}

/// A single Stored local record, with the method and CRC-32 field callers
/// choose explicitly rather than derived from the payload — so a fixture
/// can build a record whose declared checksum does not match what it holds
/// (`Partial`/checksum mismatch), or one using a recognised-but-undecodable
/// method (`Unverified`/undecodable method), the two `--list` cause labels
/// [`salvage_list_names_partial_and_unverified_causes`] checks for.
pub(crate) fn salvage_fixture_local_record_with(
    offset: u32,
    name: &'static str,
    payload: &'static [u8],
    method: u16,
    crc: u32,
) -> SalvageFixtureLocalRecord {
    let len = u32::try_from(payload.len()).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&method.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0x21u16.to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(payload);
    SalvageFixtureLocalRecord {
        offset,
        name,
        crc,
        len,
        bytes,
    }
}

/// Builds a two-entry zip: scan position 0 is Stored with a CRC-32 field
/// that disagrees with its payload (`Partial`, checksum-mismatch cause);
/// scan position 1 declares method 99 (AES — recognised by
/// `is_known_method`, not decoded by this build's salvage verifier), with a
/// correct CRC over ITS OWN bytes so only the method is what makes it
/// unverifiable (`Unverified`, undecodable-method cause).
pub(crate) fn build_partial_and_unverified_zip_fixture() -> Vec<u8> {
    let mismatched_payload: &[u8] = b"this payload's crc field below is wrong on purpose";
    let undecodable_payload: &[u8] = b"this method is recognised but this build cannot decode it";

    let mut out = Vec::new();
    let rec0 = salvage_fixture_local_record_with(
        u32::try_from(out.len()).unwrap(),
        "mismatched.bin",
        mismatched_payload,
        0, // Stored
        0xDEAD_BEEF,
    );
    out.extend_from_slice(&rec0.bytes);
    let rec1 = salvage_fixture_local_record_with(
        u32::try_from(out.len()).unwrap(),
        "undecodable.bin",
        undecodable_payload,
        99, // AES — recognised, not decoded
        salvage_fixture_crc32(undecodable_payload),
    );
    out.extend_from_slice(&rec1.bytes);

    let cd_start = u32::try_from(out.len()).unwrap();
    out.extend_from_slice(&salvage_fixture_central_record(&rec0));
    out.extend_from_slice(&salvage_fixture_central_record(&rec1));
    let cd_size = u32::try_from(out.len()).unwrap() - cd_start;

    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// One real local file header, parsed directly out of bytes the SYSTEM
/// `zip` wrote — a minimal, test-local mirror of the fixed 30-byte layout
/// `crates/stuffr-formats/src/zip_salvage.rs`'s own scanner reads (see that
/// module for the full field-by-field account). Hand-rolled here, rather
/// than depending on `stuffr-formats` at all, for the same reason this
/// file's `salvage_fixture_local_record` above hand-ASSEMBLES a local
/// header instead of reaching for a zip-writing crate: this test binary
/// has never depended on a second zip stack.
pub(crate) struct RealZipLocalEntry {
    /// Byte offset of this record's `PK\x03\x04` signature.
    pub(crate) offset: usize,
    pub(crate) name: String,
    /// Byte offset of the 4-byte `crc32` field within this record.
    pub(crate) crc_offset: usize,
    /// Byte range of this entry's (Stored, so uncompressed) payload.
    pub(crate) payload: std::ops::Range<usize>,
    /// Byte length of the WHOLE physical record (header + name + extra +
    /// payload) — what a byte-identical duplicate of this record must copy.
    pub(crate) record_len: usize,
}

/// Walks every local file header in `bytes` in file order — the same shape
/// `zip_salvage.rs`'s own raw scan performs, hand-rolled here so this test
/// binary never has to depend on that crate to damage the fixture below.
pub(crate) fn parse_real_zip_local_entries(bytes: &[u8]) -> Vec<RealZipLocalEntry> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 30 <= bytes.len() && bytes[i..i + 4] == [0x50, 0x4b, 0x03, 0x04] {
        let compressed_size =
            u32::from_le_bytes(bytes[i + 18..i + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes([bytes[i + 26], bytes[i + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[i + 28], bytes[i + 29]]) as usize;
        let name_start = i + 30;
        let name = String::from_utf8(bytes[name_start..name_start + name_len].to_vec())
            .expect("this section's own fixture names are plain ASCII");
        let payload_start = name_start + name_len + extra_len;
        let payload = payload_start..payload_start + compressed_size;
        let record_len = payload.end - i;
        out.push(RealZipLocalEntry {
            offset: i,
            name,
            crc_offset: i + 14,
            payload,
            record_len,
        });
        i += record_len;
    }
    out
}

/// Byte offset of the end-of-central-directory record. This section's own
/// fixture never carries an archive comment, so it is simply the last
/// four-byte match.
pub(crate) fn find_real_zip_eocd(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .expect("every archive this section builds must carry an EOCD record")
}

/// Builds the catalogue's one healthy archive — see this section's own
/// header comment for why it is Stored and carries no extra field. Written
/// by the SYSTEM `zip` binary, never by this project's own writer, so every
/// mutation below is damage applied to a tool-verified-good archive, not to
/// one only this project has ever agreed with itself is well-formed.
pub(crate) fn build_real_healthy_zip(dir: &Path) -> (PathBuf, [(&'static str, &'static [u8]); 3]) {
    let entries: [(&str, &[u8]); 3] = [
        ("alpha.txt", b"alpha entry payload, first in the archive"),
        ("beta.txt", b"beta entry payload, sits in the middle"),
        (
            "gamma.bin",
            b"gamma entry payload, the last one in the archive",
        ),
    ];
    let src = dir.join("src");
    std::fs::create_dir(&src).unwrap();
    for (name, data) in &entries {
        std::fs::write(src.join(name), data).unwrap();
    }
    let zip_bin = require_bin("zip");
    let archive = dir.join("healthy.zip");
    run_tool(
        &zip_bin,
        &[
            os(&"-q"),
            os(&"-0"),
            os(&"-X"),
            os(&archive),
            os(&"alpha.txt"),
            os(&"beta.txt"),
            os(&"gamma.bin"),
        ],
        &src,
        b"",
    );
    (archive, entries)
}

/// Runs `stuffr salvage ARCHIVE --list` (report-only: no `-C`, nothing is
/// ever written to disk) and returns its stdout, one string per row — the
/// same rows `describe_salvage_row` builds, in scan order, so `rows[N]`
/// below is scan position `N` whenever every damage catalogue mutation
/// leaves the earlier records discoverable (true of every mutation but the
/// truncated-tail one, which is checked by row COUNT instead).
pub(crate) fn salvage_list_rows(archive: &Path) -> Vec<String> {
    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Zeroes every byte from the central directory onward (the CD itself and
/// the EOCD both) — the index destroyed entirely, the shape
/// `zip_salvage.rs`'s "Central-directory reconciliation" section calls the
/// scan's own reason to exist. Shared between the damage catalogue's own
/// row for this mutation and the external-witness test, since both need
/// the identical damaged bytes.
pub(crate) fn mutate_zeroed_central_directory(healthy: &[u8]) -> Vec<u8> {
    let mut bytes = healthy.to_vec();
    let eocd = find_real_zip_eocd(&bytes);
    let cd_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    for b in &mut bytes[cd_offset..] {
        *b = 0;
    }
    bytes
}

/// Flips 10 bytes in the MIDDLE (`beta.txt`) entry's payload — its declared
/// length and its own CRC-32 field are untouched, and the central directory
/// is untouched too, so this is a shape a reference tool can check with a
/// plain `unzip -t`, no `-FF` recovery step needed at all. Shared between
/// the damage catalogue's own row for this mutation and the external-
/// witness test (fix round 1, REQUIRED 1), since both need the identical
/// damaged bytes.
pub(crate) fn mutate_hole_punched_mid_payload(healthy: &[u8]) -> Vec<u8> {
    let mut bytes = healthy.to_vec();
    let real_entries = parse_real_zip_local_entries(&bytes);
    let beta = &real_entries[1];
    assert!(
        beta.payload.len() >= 15,
        "sanity: room to punch a hole without running past this entry's own payload"
    );
    for b in &mut bytes[beta.payload.start + 5..beta.payload.start + 15] {
        *b ^= 0xFF;
    }
    bytes
}

/// Flips a byte of the FIRST (`alpha.txt`) entry's LOCAL-header `crc32`
/// field only — its payload and the central directory's own copy of the
/// checksum are untouched, so (like the hole-punch mutation above) this is
/// checkable with a plain `unzip -t`. Shared between the damage catalogue's
/// own row for this mutation and the external-witness test (fix round 1,
/// REQUIRED 1).
pub(crate) fn mutate_one_crc_corrupted(healthy: &[u8]) -> Vec<u8> {
    let mut bytes = healthy.to_vec();
    let real_entries = parse_real_zip_local_entries(&bytes);
    let alpha_crc_offset = real_entries[0].crc_offset;
    bytes[alpha_crc_offset] ^= 0xFF;
    bytes
}

/// Appends a byte-identical physical copy of the FIRST entry's local
/// record, and splices a matching duplicate central-directory record
/// (pointing at the copy) into the index — 4 physical records over 3
/// names, the small sibling of `stuffr-formats/src/zip.rs`'s own
/// `build_shadowing_zip` fixture (8 records, 6 names) and this file's own
/// `build_shadowing_zip_fixture` above, built here over an archive the
/// SYSTEM `zip` wrote instead of one this project hand-assembled from
/// nothing.
pub(crate) fn duplicate_first_central_directory_record(healthy: &[u8]) -> Vec<u8> {
    let bytes = healthy.to_vec();
    let eocd = find_real_zip_eocd(&bytes);
    let disk_no = u16::from_le_bytes(bytes[eocd + 4..eocd + 6].try_into().unwrap());
    let disk_cd = u16::from_le_bytes(bytes[eocd + 6..eocd + 8].try_into().unwrap());
    let cd_total = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().unwrap());
    let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
    let cd_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let comment_len = u16::from_le_bytes(bytes[eocd + 20..eocd + 22].try_into().unwrap());

    let real_entries = parse_real_zip_local_entries(&bytes);
    let first = &real_entries[0];
    let duplicate_record = bytes[first.offset..first.offset + first.record_len].to_vec();

    let old_cd = bytes[cd_offset..cd_offset + cd_size].to_vec();
    assert_eq!(
        &old_cd[0..4],
        &[0x50, 0x4b, 0x01, 0x02],
        "sanity: the central directory's first record"
    );
    let name_len = u16::from_le_bytes(old_cd[28..30].try_into().unwrap()) as usize;
    let extra_len = u16::from_le_bytes(old_cd[30..32].try_into().unwrap()) as usize;
    let comment_len_rec = u16::from_le_bytes(old_cd[32..34].try_into().unwrap()) as usize;
    let first_cd_len = 46 + name_len + extra_len + comment_len_rec;
    let mut duplicate_cd_record = old_cd[0..first_cd_len].to_vec();

    // The duplicate physical record lands exactly where the OLD central
    // directory used to start — that is where this function inserts it.
    let new_local_offset = cd_offset as u32;
    duplicate_cd_record[42..46].copy_from_slice(&new_local_offset.to_le_bytes());

    let new_cd_start = cd_offset + duplicate_record.len();
    let mut new_cd = old_cd.clone();
    new_cd.extend_from_slice(&duplicate_cd_record);
    let new_total = cd_total + 1;

    let mut out = bytes[..cd_offset].to_vec();
    out.extend_from_slice(&duplicate_record);
    out.extend_from_slice(&new_cd);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&disk_no.to_le_bytes());
    out.extend_from_slice(&disk_cd.to_le_bytes());
    out.extend_from_slice(&new_total.to_le_bytes());
    out.extend_from_slice(&new_total.to_le_bytes());
    out.extend_from_slice(&(new_cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&(new_cd_start as u32).to_le_bytes());
    out.extend_from_slice(&comment_len.to_le_bytes());
    out
}

/// Runs Info-Zip's `zip -FF` against `archive`, answering its `y/n` prompt
/// ("Is this a single-disk archive?" — the only one any fixture in this
/// section provokes) with `y`. Guards against a real failure mode measured
/// while designing this test: given a fully closed stdin instead, `zip -FF`
/// treats the immediate EOF as a blank line at its OWN "try again" prompt
/// and loops forever re-printing its default-answer menu rather than
/// exiting — a hang, not a slow pass, in the REFERENCE tool's own handling
/// of EOF, so a watchdog thread kills the child if it is still running past
/// a generous bound rather than letting a run hang indefinitely.
#[cfg(unix)]
pub(crate) fn run_zip_ff(zip_bin: &Path, archive: &Path, out: &Path) -> std::process::Output {
    let mut child = Command::new(zip_bin)
        .args([os(&"-FF"), os(&archive), os(&"--out"), os(&out)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"y\ny\ny\ny\ny\n")
        .unwrap();

    let pid = child.id();
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished_for_watchdog = finished.clone();
    let watchdog = std::thread::spawn(move || {
        for _ in 0..200 {
            if finished_for_watchdog.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    });

    let output = child.wait_with_output().unwrap();
    finished.store(true, Ordering::Relaxed);
    watchdog.join().unwrap();
    output
}

/// Runs `unzip -t ARCHIVE` directly — no `-FF` recovery step and no
/// interactive prompt, because the two mutations this is used for
/// (fix round 1, REQUIRED 1) leave the central directory untouched, so
/// `unzip` reads the index exactly as it would for a healthy archive and
/// only its PER-ENTRY decode/CRC-32 check can fail. Returns stdout, one
/// line per entry (plus header/footer lines). Exit status is deliberately
/// not asserted here: a damaged entry makes `unzip -t` exit non-zero by
/// design, and the callers below check per-entry lines, not the process
/// exit code.
pub(crate) fn unzip_test_lines(unzip_bin: &Path, archive: &Path) -> Vec<String> {
    let out = Command::new(unzip_bin)
        .args(["-t", archive.to_str().unwrap()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The line naming `name` within `unzip -t`'s output — panics (never
/// silently returns nothing) if `name` is missing entirely, since that
/// would mean the reference tool lost the entry outright rather than
/// merely disagreeing about its checksum.
pub(crate) fn unzip_test_line_for<'a>(lines: &'a [String], name: &str) -> &'a str {
    lines
        .iter()
        .map(String::as_str)
        .find(|l| l.contains(name))
        .unwrap_or_else(|| panic!("`unzip -t` must still report on `{name}`: {lines:?}"))
}

/// A checked-in legacy fixture, by path relative to
/// `crates/stuffr-formats/fixtures/legacy/`. `CARGO_MANIFEST_DIR` bakes an
/// absolute path at compile time — see `workspace_source_files` above for
/// the same hazard and the same fix.
pub(crate) fn legacy_fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("stuffr-formats")
        .join("fixtures")
        .join("legacy")
        .join(rel)
}

/// Runs the truncated-tail catalogue row end to end over one archive.
///
/// `drop_bytes` is cut from the END of the file, which lands inside the
/// LAST entry's payload for every fixture named below (each format's
/// trailer — ARC's two-byte marker, ZOO's 56-byte terminator record, LHA's
/// one-byte marker, ARJ's four-byte marker — is smaller than the amount
/// cut).
///
/// **The expectation is the pre-damage state throughout.** `expected_names`
/// is what the archive held before anything was cut, asserted against the
/// HEALTHY file first; the recovered prefix is compared against the healthy
/// archive's own content for that entry, read back with `cat --index`
/// before the cut is made.
pub(crate) fn legacy_truncated_tail_row(
    label: &str,
    fixture: &str,
    drop_bytes: usize,
    expected_names: &[&str],
) {
    let dir = tmp_dir();
    let healthy_path = legacy_fixture(fixture);
    let healthy = std::fs::read(&healthy_path).unwrap();

    // 1. The pre-damage state, established before anything is damaged.
    let rows = salvage_list_rows(&healthy_path);
    assert_eq!(
        rows.len(),
        expected_names.len(),
        "{label}: sanity, the UNDAMAGED archive's own row count: {rows:?}"
    );
    for (row, name) in rows.iter().zip(expected_names) {
        assert!(
            row.contains(name) && row.contains("Intact"),
            "{label}: every entry of the undamaged archive must verify Intact: {row}"
        );
    }
    let last_index = expected_names.len() - 1;
    let out = run_output(&[
        "cat",
        "--index",
        &last_index.to_string(),
        healthy_path.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{label}: the undamaged archive's last entry must read back cleanly: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let went_in = out.stdout;
    assert!(
        !went_in.is_empty(),
        "{label}: the last entry must carry a payload for this row to mean anything"
    );

    // 2. The damage.
    let cut = healthy.len() - drop_bytes;
    let damaged = dir.join(format!("truncated-{}", fixture.replace('/', "-")));
    std::fs::write(&damaged, &healthy[..cut]).unwrap();

    // 3. Every earlier entry still Intact, the cut one named and named as
    //    TRUNCATED rather than as a bad checksum — the payload ran out,
    //    nothing disagreed.
    let rows = salvage_list_rows(&damaged);
    assert_eq!(
        rows.len(),
        expected_names.len(),
        "{label}: the cut entry's header is still there and its being uncompletable is a \
         fact worth a row, never silence: {rows:?}"
    );
    for (i, (row, name)) in rows.iter().zip(expected_names).enumerate() {
        assert!(row.contains(name), "{label}: {row}");
        if i == last_index {
            assert!(
                row.contains("Partial (truncated)"),
                "{label}: the cut entry must be named as truncated: {row}"
            );
        } else {
            assert!(
                row.contains("Intact"),
                "{label}: an entry before the cut is untouched: {row}"
            );
        }
    }

    // 4. The run must not exit 0, and the surviving prefix lands under
    //    `.partial` — never under the entry's real name.
    let out_dir = dir.join(format!("recovered-{}", fixture.replace('/', "-")));
    let out = run_output(&[
        "salvage",
        damaged.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{label}: a run that could not complete something must not exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let partial = out_dir.join(format!("{}.partial", expected_names[last_index]));
    assert!(
        partial.is_file(),
        "{label}: expected {} on disk",
        partial.display()
    );
    assert!(
        !out_dir.join(expected_names[last_index]).exists(),
        "{label}: an incomplete entry must never land under its real name"
    );
    for name in &expected_names[..last_index] {
        let recovered = std::fs::read(out_dir.join(name)).unwrap_or_else(|e| {
            panic!("{label}: an entry before the cut must be recovered whole: {e}")
        });
        assert!(!recovered.is_empty(), "{label}: `{name}` came back empty");
    }

    // 5. **Not one invented byte.** What is on disk is exactly a prefix of
    //    what went in, and strictly shorter than it. `zip -FF` fills the
    //    gap from its own buffer and calls the result fixed; this is the
    //    assertion that says stuffr does not.
    let recovered = std::fs::read(&partial).unwrap();
    assert!(
        !recovered.is_empty() && recovered.len() < went_in.len(),
        "{label}: {} recovered bytes against {} that went in",
        recovered.len(),
        went_in.len()
    );
    assert_eq!(
        recovered[..],
        went_in[..recovered.len()],
        "{label}: every recovered byte must be one the archive itself still held"
    );
}

/// One POSIX ustar entry, as Python's `tarfile` writes one (`ustar\0` `00`
/// magic, typeflag `0`, `%06o\0 ` checksum): [`v7_tar_entry`] with the magic
/// and typeflag set and the checksum recomputed. With a name and payload
/// that start with the same byte, its header seen one byte late agrees with
/// its own checksum — the plain-sum shift `tar_salvage.rs` documents.
pub(crate) fn ustar_tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let mut b = v7_tar_entry(name, data, b"ustar\x0000");
    b[156] = b'0';
    b[148..156].fill(b' ');
    let sum: u32 = b[..512].iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

/// One v7-style tar entry: a header with `magic` over bytes 257..265 and a
/// correct `%06o\0 ` checksum (GNU tar's spelling), then `data` padded to a
/// whole block. Built by hand: nothing in reach writes junk into a v7
/// header's padding on purpose.
pub(crate) fn v7_tar_entry(name: &str, data: &[u8], magic: &[u8; 8]) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name.as_bytes());
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0000000\0");
    b[116..124].copy_from_slice(b"0000000\0");
    b[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    b[136..148].copy_from_slice(b"14727046122\0");
    b[257..265].copy_from_slice(magic);
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b.extend_from_slice(data);
    b.resize(b.len().div_ceil(512) * 512, 0);
    b
}

/// One `newc` entry built by hand — magic, thirteen 8-digit hex fields,
/// the NUL-terminated name, padding to four, the payload, padding to four —
/// so the fixture depends on nothing but the format's own layout.
pub(crate) fn newc_entry(magic: &[u8; 6], name: &str, data: &[u8]) -> Vec<u8> {
    let fields: [u32; 13] = [
        1,
        0o100644,
        0,
        0,
        1,
        0x5F00_0000,
        data.len() as u32,
        0,
        0,
        0,
        0,
        name.len() as u32 + 1,
        0,
    ];
    let mut out = magic.to_vec();
    for field in fields {
        out.extend_from_slice(format!("{field:08X}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.resize(out.len().div_ceil(4) * 4, 0);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(4) * 4, 0);
    out
}

pub(crate) fn newc_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = entries
        .iter()
        .flat_map(|(name, data)| newc_entry(b"070701", name, data))
        .collect();
    out.extend_from_slice(&newc_entry(b"070701", "TRAILER!!!", b""));
    out
}

/// One plain `ar` member: a short name, placeholder fields, and the `\n` pad
/// after an odd-sized payload — the common layout every writer shares.
pub(crate) fn ar_member(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0,
        0,
        0,
        "100644",
        data.len()
    )
    .into_bytes();
    assert_eq!(out.len(), 60);
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
    out
}

pub(crate) fn ar_archive(entries: &[(&str, &[u8])]) -> (Vec<u8>, Vec<usize>) {
    let mut out = b"!<arch>\n".to_vec();
    let mut offsets = Vec::new();
    for (name, data) in entries {
        offsets.push(out.len());
        out.extend(ar_member(name, data));
    }
    (out, offsets)
}

/// The files every writer is fed. Each payload is over a kilobyte, so a
/// flip at its middle is far from any header (a cpio `newc` header is 110
/// bytes plus the name), and each is distinct, so finding it in the archive
/// is unambiguous.
pub(crate) fn checksumless_inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "alpha.txt",
            (0..200)
                .flat_map(|i| format!("alpha line {i}\n").into_bytes())
                .collect(),
        ),
        (
            "beta.txt",
            (0..301)
                .flat_map(|i| format!("beta {i};").into_bytes())
                .collect(),
        ),
        (
            "gamma.bin",
            (0..1500u32).map(|i| ((i * 7 + 3) % 256) as u8).collect(),
        ),
        (
            "delta.txt",
            (0..151)
                .flat_map(|i| format!("delta row {i}\n").into_bytes())
                .collect(),
        ),
    ]
}

/// The platform tool's archive of [`checksumless_inputs`], in `dir`.
pub(crate) fn checksumless_archive(format: &str, dir: &Path) -> Vec<u8> {
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let inputs = checksumless_inputs();
    for (name, data) in &inputs {
        std::fs::write(tree.join(name), data).unwrap();
    }
    let names: Vec<&std::ffi::OsStr> = inputs.iter().map(|(n, _)| os(n)).collect();
    match format {
        "tar" => {
            let out = dir.join("ref.tar");
            let mut args = vec![os(&"--format=ustar"), os(&"-cf"), os(&out)];
            args.extend(&names);
            run_tool(&require_bin("tar"), &args, &tree, b"");
            std::fs::read(out).unwrap()
        }
        "cpio" => {
            let list: Vec<&str> = inputs.iter().map(|(n, _)| *n).collect();
            run_tool(
                &require_bin("cpio"),
                &[os(&"-o"), os(&"-H"), os(&"newc")],
                &tree,
                list.join("\n").as_bytes(),
            )
        }
        "ar" => {
            let out = dir.join("ref.a");
            let mut args = vec![os(&"rcS"), os(&out)];
            args.extend(&names);
            run_tool(&require_bin("ar"), &args, &tree, b"");
            std::fs::read(out).unwrap()
        }
        other => panic!("no writer for {other}"),
    }
}

/// Where `data` starts in `archive` — asserted to occur exactly once.
pub(crate) fn payload_offset(archive: &[u8], data: &[u8]) -> usize {
    let hits: Vec<usize> = archive
        .windows(data.len())
        .enumerate()
        .filter(|(_, w)| *w == data)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "an input's bytes must appear exactly once");
    hits[0]
}

/// The three rows over one format, end to end. `tier` is the best the
/// format can say (`Complete` for tar, `Unattested` for cpio and ar) and
/// `whole_exit` the code a run with nothing worse exits with (0 and 4).
pub(crate) fn checksumless_catalogue_end_to_end(format: &str, tier: &str, whole_exit: i32) {
    let dir = tmp_dir();
    let healthy = checksumless_archive(format, &dir);
    let inputs = checksumless_inputs();
    let row_of = |rows: &[String], name: &str| -> String {
        rows.iter()
            .find(|r| r.split_whitespace().any(|w| w == name))
            .unwrap_or_else(|| panic!("{format}: no row for {name}: {rows:?}"))
            .clone()
    };

    // 0. The undamaged archive: every input listed at the format's tier.
    let path = dir.join(format!("healthy.{format}"));
    std::fs::write(&path, &healthy).unwrap();
    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), inputs.len(), "{format}: {rows:?}");
    for (name, _) in &inputs {
        assert!(row_of(&rows, name).contains(tier), "{format}: {rows:?}");
    }

    // 1. A byte flipped mid-payload of `beta.txt`: still listed at the
    //    format's tier, never `Intact`; written under its REAL name at the
    //    ordinary exit code; and wrong on disk in exactly that byte.
    let (beta, beta_data) = (&inputs[1].0, &inputs[1].1);
    let mid = beta_data.len() / 2;
    let mut flipped = healthy.clone();
    flipped[payload_offset(&healthy, beta_data) + mid] ^= 0xFF;
    let path = dir.join(format!("flipped.{format}"));
    std::fs::write(&path, &flipped).unwrap();
    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), inputs.len(), "{format}: {rows:?}");
    assert!(row_of(&rows, beta).contains(tier), "{format}: {rows:?}");
    assert!(
        rows.iter().all(|r| !r.contains("Intact")),
        "{format}: `Intact` claims a content check this format does not carry: {rows:?}"
    );
    let out_dir = dir.join(format!("flipped-{format}"));
    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(whole_exit),
        "{format}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut wrong = beta_data.clone();
    wrong[mid] ^= 0xFF;
    assert_eq!(
        std::fs::read(out_dir.join(beta)).unwrap(),
        wrong,
        "{format}: the silently wrong file, wrong in exactly the flipped byte"
    );
    for (name, data) in inputs.iter().filter(|(n, _)| n != beta) {
        assert_eq!(
            &std::fs::read(out_dir.join(name)).unwrap(),
            data,
            "{format}"
        );
    }

    // 2. A truncated tail, cut halfway through `delta.txt`: the earlier
    //    three at the format's tier and whole on disk, the cut one
    //    `Partial (truncated)`, its genuine prefix as `.partial`, exit 4.
    let (delta, delta_data) = (&inputs[3].0, &inputs[3].1);
    let keep = delta_data.len() / 2;
    let path = dir.join(format!("cut.{format}"));
    std::fs::write(
        &path,
        &healthy[..payload_offset(&healthy, delta_data) + keep],
    )
    .unwrap();
    let rows = salvage_list_rows(&path);
    assert_eq!(rows.len(), inputs.len(), "{format}: {rows:?}");
    assert!(
        row_of(&rows, delta).contains("Partial (truncated)"),
        "{format}: {rows:?}"
    );
    let out_dir = dir.join(format!("cut-{format}"));
    let out = run_output(&[
        "salvage",
        path.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{format}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join(format!("{delta}.partial"))).unwrap(),
        delta_data[..keep],
        "{format}: exactly the surviving prefix, nothing invented"
    );
    assert!(!out_dir.join(delta).exists(), "{format}");
    for (name, data) in &inputs[..3] {
        assert!(row_of(&rows, name).contains(tier), "{format}: {rows:?}");
        assert_eq!(
            &std::fs::read(out_dir.join(name)).unwrap(),
            data,
            "{format}"
        );
    }
}

/// The two payloads `convert_fixture` packs, for byte-for-byte comparison.
pub(crate) fn convert_payloads() -> (Vec<u8>, Vec<u8>) {
    (
        b"first file, compressible enough to matter\n".repeat(50),
        (0u8..=255).collect(),
    )
}

/// A fresh scratch directory holding `d/one.txt` and `d/sub/two.bin`, packed
/// by stuffr itself into `a.tar.gz`. Returns `(dir, a.tar.gz)`.
pub(crate) fn convert_fixture() -> (Scratch, PathBuf) {
    let dir = tmp_dir();
    let d = dir.join("d");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    let (one, two) = convert_payloads();
    std::fs::write(d.join("one.txt"), one).unwrap();
    std::fs::write(d.join("sub/two.bin"), two).unwrap();
    let a = dir.join("a.tar.gz");
    let out = run_output(&["pack", d.to_str().unwrap(), "-o", a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    (dir, a)
}

pub(crate) fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `stuffr unpack ARCHIVE -C dir/LABEL` reproduces `convert_fixture`'s files.
pub(crate) fn assert_unpacks_to_the_fixture(dir: &Path, archive: &Path, label: &str) {
    let dest = dir.join(label);
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let (one, two) = convert_payloads();
    assert_eq!(std::fs::read(dest.join("d/one.txt")).unwrap(), one);
    assert_eq!(std::fs::read(dest.join("d/sub/two.bin")).unwrap(), two);
}

/// A gzip-named file whose header is garbage: opening it is exit 5.
pub(crate) fn convert_corrupt_gz(dir: &Path) -> PathBuf {
    let bad = dir.join("bad.tar.gz");
    let mut bytes = vec![0x1f, 0x8b, 0x08, 0xff];
    bytes.extend_from_slice(&[0xde; 64]);
    std::fs::write(&bad, bytes).unwrap();
    bad
}

/// A `.tar.gz` the way `gtar czf` writes one — the tar padded with zeros to
/// a whole 10240-byte record — and a copy with one bit flipped inside the
/// stored payload. Returns `(dir, clean, corrupt)`.
///
/// The padding is what made the codec's trailer unreachable: the tar reader
/// stops at its end-of-archive blocks, the padding and the gzip CRC/ISIZE
/// behind it are never read, and the flip went unseen by every read verb
/// (Phase 5a final review, C1). stuffr's own writer pads nothing, so its
/// `.tar.gz` hides the defect. `Compression::none()` stores every deflate
/// block, so the flip changes a payload byte and nothing else: the stream
/// decodes in full, and only the CRC can tell.
pub(crate) fn gnu_padded_tar_gz() -> (Scratch, PathBuf, PathBuf) {
    let dir = tmp_dir();
    let payload: Vec<u8> = (0..4000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        append_tar_entry(&mut builder, "t/f.txt", &payload);
        builder.finish().unwrap();
    }
    tar_bytes.resize(tar_bytes.len().div_ceil(10240) * 10240, 0);
    let mut enc = GzEncoder::new(Vec::new(), Compression::none());
    enc.write_all(&tar_bytes).unwrap();
    let mut gz = enc.finish().unwrap();
    let clean = dir.join("clean.tar.gz");
    std::fs::write(&clean, &gz).unwrap();

    let probe = &payload[1000..1032];
    let at = gz
        .windows(probe.len())
        .position(|w| w == probe)
        .expect("premise: an uncompressed deflate stream stores the payload verbatim");
    gz[at + 16] ^= 0x01;
    let corrupt = dir.join("corrupt.tar.gz");
    std::fs::write(&corrupt, &gz).unwrap();
    // The premise, through the codec path that always read to the end.
    let out = run_output(&[
        "unpack",
        corrupt.to_str().unwrap(),
        "-o",
        dir.join("premise.tar").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_text(&out));
    (dir, clean, corrupt)
}

/// Every container this build can WRITE, with the extension `pack` takes it
/// from and the caps that predict what a conversion into it must drop.
pub(crate) fn writable_containers() -> Vec<(String, String, stuffr::ContainerCaps)> {
    let registry = stuffr::registry();
    registry
        .matrix()
        .into_iter()
        .filter(|row| row.write)
        .filter_map(|row| {
            let caps = registry.container(row.id)?.caps();
            let ext = row.extensions.first()?;
            Some((row.id.to_string(), ext.to_string(), caps))
        })
        .collect()
}

/// The fidelity warnings converting `source` into a container with `dst`'s
/// caps must report: one skip per entry kind the target has no shape for,
/// and — into a target that stores an owner (`stores_ownership`) — one
/// `uid_gid` per entry the source carries no ownership for (a zip, say):
/// `pack`'s rules, applied to the entries the SOURCE actually holds.
/// Returns `(skips, ownership)`.
pub(crate) fn predicted_convert_warnings(
    source: &Path,
    dst: &stuffr::ContainerCaps,
) -> (usize, usize) {
    let (metas, outcome) = stuffr::entries::list(
        stuffr::ops::Input::Path(source.to_path_buf()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .unwrap();
    assert!(
        !outcome.fidelity.has_warnings(),
        "the source itself reads with warnings, so the prediction would be wrong: {:?}",
        outcome.fidelity.warnings
    );
    let skips = metas
        .iter()
        .filter(|m| match m.kind {
            stuffr::EntryKind::Dir => !dst.stores_dirs,
            stuffr::EntryKind::Symlink { .. } => !dst.stores_symlinks,
            _ => false,
        })
        .count();
    let ownership = metas
        .iter()
        .filter(|m| dst.stores_ownership && (m.uid.is_none() || m.gid.is_none()))
        .count();
    (skips, ownership)
}

/// An ar archive in the BSD extended form (`#1/N`), whose member names may
/// hold any byte — a NUL included.
pub(crate) fn bsd_ar_with_names(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    // Every name here is of EVEN length: the `ar` crate pads a `#1/N`
    // member by its PAYLOAD's parity, so an odd-length name with an odd total
    // would be framed differently than written.
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let field = |s: String, w: usize| format!("{s:<w$}").into_bytes();
        out.extend(field(format!("#1/{}", name.len()), 16));
        out.extend(field("0".into(), 12));
        out.extend(field("0".into(), 6));
        out.extend(field("0".into(), 6));
        out.extend(field("100644".into(), 8));
        out.extend(field((name.len() + data.len()).to_string(), 10));
        out.extend(b"`\n");
        out.extend(*name);
        out.extend(*data);
        if out.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// GNU cpio, wherever this platform keeps it: the keg-only Homebrew one on
/// macOS (`reference-tools.md`), else a `cpio` on PATH whose `--version`
/// says GNU. Missing is a failure naming the fix, never a silent pass.
pub(crate) fn require_gnu_cpio() -> PathBuf {
    if cfg!(target_os = "macos") {
        let gnu = PathBuf::from("/opt/homebrew/opt/cpio/bin/cpio");
        assert!(
            gnu.is_file(),
            "GNU cpio not at {} (`brew install cpio`)",
            gnu.display()
        );
        return gnu;
    }
    let cpio = require_bin("cpio");
    let out = Command::new(&cpio).arg("--version").output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("GNU cpio"),
        "the `cpio` on PATH is not GNU cpio"
    );
    cpio
}

/// `a` with two more names (`a1`, `a2`), an empty file `e` with a second
/// name `e2`, and a plain file `p`.
#[cfg(unix)]
pub(crate) fn hard_link_tree(dir: &Path) -> PathBuf {
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a"), b"alpha payload").unwrap();
    std::fs::hard_link(tree.join("a"), tree.join("a1")).unwrap();
    std::fs::hard_link(tree.join("a"), tree.join("a2")).unwrap();
    std::fs::write(tree.join("e"), b"").unwrap();
    std::fs::hard_link(tree.join("e"), tree.join("e2")).unwrap();
    std::fs::write(tree.join("p"), b"plain").unwrap();
    tree
}

/// The groups share an inode with the expected link count, every name holds
/// the original bytes, the run exits 0 and warns about nothing.
#[cfg(unix)]
pub(crate) fn assert_links_recreated(out: &std::process::Output, dest: &Path) {
    use std::os::unix::fs::MetadataExt;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(
        !stderr.contains("skipped") && !stderr.contains("warning"),
        "a recreated link is no loss: {stderr}"
    );
    let md = |n: &str| std::fs::symlink_metadata(dest.join(n)).unwrap();
    let a = md("a");
    assert_eq!(a.nlink(), 3, "`a` and its two links");
    for n in ["a1", "a2"] {
        assert_eq!(md(n).ino(), a.ino(), "{n} shares `a`'s inode");
        assert_eq!(std::fs::read(dest.join(n)).unwrap(), b"alpha payload");
    }
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha payload");
    let e = md("e");
    assert_eq!(e.nlink(), 2);
    assert_eq!(md("e2").ino(), e.ino());
    assert_eq!(e.len(), 0);
    assert_eq!(md("p").nlink(), 1);
    assert_eq!(std::fs::read(dest.join("p")).unwrap(), b"plain");
}

/// A GNU tar of `hard_link_tree`, its entries named `./a` and so on.
#[cfg(unix)]
pub(crate) fn gnu_tar_of_hard_link_tree(dir: &Path) -> PathBuf {
    let tree = hard_link_tree(dir);
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[os(&"-cf"), os(&tar), os(&"-C"), os(&tree), os(&".")],
        dir,
        b"",
    );
    tar
}

/// Unpacks `entries` (file name, data) from a tar into a fresh directory and
/// returns stderr. `None` when the scratch filesystem does not fold `fold_a`
/// onto `fold_b` (case-sensitive volume), so the test has nothing to say.
pub(crate) fn unpack_folded(
    entries: &[(&str, &[u8])],
    fold_a: &str,
    fold_b: &str,
) -> Option<String> {
    let dir = tmp_dir();
    std::fs::write(dir.join(fold_a), b"probe").unwrap();
    let folds = std::fs::symlink_metadata(dir.join(fold_b)).is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    if !folds {
        return None;
    }
    let dir = tmp_dir();
    let tar = dir.join("f.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        for (name, data) in entries {
            append_tar_entry(&mut builder, name, data);
        }
        builder.finish().unwrap();
    }
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
    Some(stderr)
}

/// An Info-ZIP fixture's bytes, or `None` when the fixture directory is absent
/// (it is excluded from the published `stuffr-formats` crate; ruling P8). A
/// named file missing from a present directory panics.
pub(crate) fn infozip_fixture(name: &str) -> Option<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../stuffr-formats/tests/data/infozip");
    if !dir.is_dir() {
        eprintln!("note: {} is absent; skipping", dir.display());
        return None;
    }
    Some(std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}")))
}

pub(crate) fn bench_err(args: &[&str]) -> (Option<i32>, String) {
    let out = run_output(args);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A real gzip stream of exactly `len` bytes whose decoded content is
/// `content` followed by zeros: stored deflate blocks, so the size is exact.
/// `stuffr ls` lists only streams whose header checks out, and a magic
/// followed by noise is not one; this is how a test gets a real `.gz` of the
/// size its expected row prints. `len` must leave room for `content` and the
/// 23 bytes of framing (header, one block header, trailer).
pub(crate) fn stored_gzip(content: &[u8], len: usize) -> Vec<u8> {
    const BLOCK: usize = 65_535;
    let body = len.checked_sub(18).expect("room for the gzip framing");
    let blocks = body.div_ceil(BLOCK + 5).max(1);
    let data_len = body - 5 * blocks;
    assert!(
        data_len >= content.len(),
        "{len} bytes cannot hold the content"
    );
    let mut data = content.to_vec();
    data.resize(data_len, 0);
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks: Vec<&[u8]> = data.chunks(BLOCK).collect();
    while chunks.len() < blocks {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.iter().enumerate() {
        let n = chunk.len() as u16;
        out.push(u8::from(i == last));
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&salvage_fixture_crc32(&data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    assert_eq!(out.len(), len);
    out
}

/// A real tar holding one file, `a.txt` = `alpha` (GNU header, via the `tar`
/// crate).
pub(crate) fn small_tar() -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        append_tar_entry(&mut builder, "a.txt", b"alpha");
        builder.finish().unwrap();
    }
    tar_bytes
}

/// A real stored zip of exactly `len` bytes: one entry `a` holding zeros.
/// `len` must be at least 100 (the framing of a one-letter name).
pub(crate) fn stored_zip(len: usize) -> Vec<u8> {
    let data = vec![0u8; len.checked_sub(100).expect("room for the zip framing")];
    let crc = salvage_fixture_crc32(&data);
    let size = data.len() as u32;
    let mut out = Vec::with_capacity(len);
    // Local header: version 10, no flags, stored, a fixed DOS time.
    out.extend_from_slice(b"PK\x03\x04\x0a\0\0\0\0\0\xa1\x82\x5e\x5d");
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&[1, 0, 0, 0, b'a']);
    out.extend_from_slice(&data);
    let central = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02\x1e\x03\x0a\0\0\0\0\0\xa1\x82\x5e\x5d");
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    // Name length 1, no extra, no comment, disk 0, internal 0, external
    // 0o100644 << 16, local header at 0.
    out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa4, 0x81]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(b'a');
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0\x2f\0\0\0");
    out.extend_from_slice(&central.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    assert_eq!(out.len(), len);
    out
}

/// `xz -c </dev/null`: the smallest real xz stream (32 bytes).
pub(crate) const EMPTY_XZ: &[u8] = &[
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0, 0, 0, 0, 0x1c, 0xdf, 0x44,
    0x21, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0, 0, 0, 0, 0x04, 0x59, 0x5a,
];
