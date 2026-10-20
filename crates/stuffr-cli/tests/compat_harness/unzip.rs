//! The unzip family's part of the differential harness (0.16.0): the
//! reference lookup, the tree snapshot, the comparison and the archive
//! helpers only unzip needs. Re-exported by `compat_harness`, so suites
//! call it as `compat_harness::...`.

use super::*;

/// The Ubuntu reference: apt's `unzip` on ubuntu 24.04 (`dpkg-query -W -f
/// '${Version}' unzip`).
pub const UBUNTU_UNZIP_VERSION: &str = "6.0-28ubuntu4.1";

/// The first line of each reference program's usage and `-v` (R2: stuffr's
/// own first line names stuffr instead; [`unzip_differences`] masks both).
pub const APPLE_UNZIP_BANNER: &str =
    "UnZip 6.00 of 20 April 2009, by Info-ZIP, with modifications by Apple Inc.";
pub const UBUNTU_UNZIP_BANNER: &str =
    "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.";
/// zipinfo's, the same in both builds.
pub const ZIPINFO_BANNER: &str =
    "ZipInfo 3.00 of 20 April 2009, by Greg Roelofs and the Info-ZIP group.";
/// funzip's, the same in both builds (its usage, shown only when standard
/// input is a terminal).
pub const FUNZIP_BANNER: &str = "fUnZip (filter UnZip), version 3.95 of 20 January 2009";

/// `/usr/bin/unzip -v` of the Mac the Apple suite was verified against
/// (R11). Another macOS may ship another build; [`compare_unzip`] then
/// says so in every difference.
pub const APPLE_UNZIP_IDENTITY: &str = concat!(
    "UnZip 6.00 of 20 April 2009, by Info-ZIP, with modifications by Apple Inc.\n",
    "Please report bugs to Apple.\n",
    "\n",
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip/ ;\n",
    "see ftp://ftp.info-zip.org/pub/infozip/UnZip.html for other sites.\n",
    "\n",
    "Compiled with gcc Apple LLVM 21.0.0 (clang-2100.3.31.1) [+internal-os] for Unix Mac OS X on Aug  8 2026.\n",
    "\n",
    "UnZip special compilation options:\n",
    "        COPYRIGHT_CLEAN (PKZIP 0.9x unreducing method not supported)\n",
    "        SET_DIR_ATTRIB\n",
    "        SYMLINKS (symbolic links supported, if RTL and file system permit)\n",
    "        TIMESTAMP\n",
    "        UNIXBACKUP\n",
    "        USE_EF_UT_TIME\n",
    "        USE_UNSHRINK (PKZIP/Zip 1.x unshrinking method supported)\n",
    "        USE_DEFLATE64 (PKZIP 4.x Deflate64(tm) supported)\n",
    "        LARGE_FILE_SUPPORT (large files over 2 GiB supported)\n",
    "        ZIP64_SUPPORT (archives using Zip64 for large files supported)\n",
    "        VMS_TEXT_CONV\n",
    "        [decryption, version 2.11 of 05 Jan 2007]\n",
    "\n",
    "UnZip and ZipInfo environment options:\n",
    "           UNZIP:  [none]\n",
    "        UNZIPOPT:  [none]\n",
    "         ZIPINFO:  [none]\n",
    "      ZIPINFOOPT:  [none]\n",
);

/// The flavour whose reference this platform has: `apple` on macOS and
/// the BSDs, `ubuntu` elsewhere (the family's own default, plan
/// "Flavour selection").
pub fn platform_unzip_flavour() -> &'static str {
    if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        "apple"
    } else {
        "ubuntu"
    }
}

/// The installed apt `unzip` package's version, `None` without `dpkg-query`
/// or the package.
pub fn ubuntu_unzip_version() -> Option<String> {
    let out = output(
        Command::new("dpkg-query")
            .args(["-W", "-f", "${Version}", "unzip"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null()),
    )
    .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The directory of the platform's unzip reference (`unzip`, `zipinfo`,
/// `funzip`), R3: `/usr/bin` on macOS (Apple's build), and `/usr/bin` on
/// Linux only when the apt package is [`UBUNTU_UNZIP_VERSION`]: another
/// release is no reference (CI's ubuntu-latest and `make compat-ubuntu`
/// have it). Elsewhere there is none.
///
/// `None`: a skip with a note locally, a panic under `CI` (the rule of
/// [`require_reference`]), so a suite cannot pass vacuously.
pub fn unzip_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Result<&'static str, String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        if !Path::new("/usr/bin/unzip").is_file() {
            return Err("there is no /usr/bin/unzip".to_owned());
        }
        if cfg!(target_os = "macos") {
            Ok("/usr/bin")
        } else if cfg!(target_os = "linux") {
            match ubuntu_unzip_version() {
                Some(v) if v == UBUNTU_UNZIP_VERSION => Ok("/usr/bin"),
                Some(v) => Err(format!(
                    "the apt unzip is {v}, not {UBUNTU_UNZIP_VERSION} (`make compat-ubuntu` has it)"
                )),
                None => Err("/usr/bin/unzip is not apt's unzip package".to_owned()),
            }
        } else {
            Err("this platform has no unzip reference".to_owned())
        }
    });
    match found {
        Ok(d) => Some(d),
        Err(why) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no unzip reference: {why}"
            );
            eprintln!("skipped: no unzip reference ({why})");
            None
        }
    }
}

/// The installed Apple reference's `unzip -v` (standard output, `LANG=C`),
/// cached; `None` off macOS or without `/usr/bin/unzip`. Compared with
/// [`APPLE_UNZIP_IDENTITY`] by [`compare_unzip`] (R11).
pub fn apple_unzip_identity() -> Option<&'static str> {
    static V: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let out = output(
            Command::new("/usr/bin/unzip")
                .arg("-v")
                .env_clear()
                .env("LANG", "C")
                .stdin(Stdio::null()),
        )
        .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    })
    .as_deref()
}

/// A case for the unzip family: `name` (`unzip`, `zipinfo`, `funzip`) with
/// `args` over `files`, standard input empty (a pipe of nothing is `None`:
/// `/dev/null`), `TZ=UTC`, and stuffr forced to this platform's flavour
/// ([`platform_unzip_flavour`]). A suite of the other flavour sets
/// `unzip_flavour` itself.
pub fn unzip_case<'a>(
    name: &'a str,
    args: Vec<&'a str>,
    files: Vec<(&'a str, Vec<u8>)>,
) -> Case<'a> {
    Case {
        name,
        args,
        files,
        stdin: None,
        tty_stdin: false,
        tty_stdout: false,
        env: vec![],
        compare_output_bytes: true,
        expect_stdout_plain: None,
        setup: None,
        // Unused: unzip's outputs are compared byte for byte, never decoded.
        roundtrip: Roundtrip::Bzip2,
        tz: None,
        unzip_flavour: Some(platform_unzip_flavour()),
    }
}

/// The quarantine attribute Apple's unzip propagates (R9).
#[cfg(target_os = "macos")]
const QUARANTINE: &std::ffi::CStr = c"com.apple.quarantine";

/// Give `path` (not following a symlink) the quarantine attribute `value`,
/// as a downloaded archive has it.
#[cfg(target_os = "macos")]
pub fn set_quarantine(path: &Path, value: &[u8]) {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: both strings are NUL-terminated and live across the call;
    // `value` is valid for `value.len()` bytes.
    let rc = unsafe {
        libc::setxattr(
            p.as_ptr(),
            QUARANTINE.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    assert_eq!(
        rc,
        0,
        "setxattr {path:?}: {}",
        std::io::Error::last_os_error()
    );
}

/// The quarantine attribute of `path` (not following a symlink), `None`
/// when it has none.
#[cfg(target_os = "macos")]
fn quarantine_of(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let get = |buf: *mut libc::c_void, len: usize| {
        // SAFETY: both strings are NUL-terminated; `buf` is null with
        // `len` 0 (a size query) or valid for `len` bytes.
        unsafe {
            libc::getxattr(
                p.as_ptr(),
                QUARANTINE.as_ptr(),
                buf,
                len,
                0,
                libc::XATTR_NOFOLLOW,
            )
        }
    };
    let n = get(std::ptr::null_mut(), 0);
    if n < 0 {
        return None;
    }
    let mut v = vec![0u8; n as usize];
    let got = get(v.as_mut_ptr().cast(), v.len());
    assert!(
        got >= 0,
        "getxattr {path:?}: {}",
        std::io::Error::last_os_error()
    );
    v.truncate(got as usize);
    Some(v)
}

#[cfg(not(target_os = "macos"))]
fn quarantine_of(_: &Path) -> Option<Vec<u8>> {
    None
}

/// One entry of an [`UnzipTree`]: what unzip can set on it.
#[derive(Debug, PartialEq)]
pub enum UnzipNode {
    /// A regular file (a FIFO or other special file reads as `<special>`,
    /// never opened; an unreadable file as `<unreadable>`).
    File {
        bytes: Vec<u8>,
        mode: u32,
        mtime: i64,
        quarantine: Option<Vec<u8>>,
    },
    Dir {
        mode: u32,
        mtime: i64,
        quarantine: Option<Vec<u8>>,
    },
    /// By `lstat`; its mtime is not compared (unzip does not set it).
    Symlink {
        target: Vec<u8>,
        quarantine: Option<Vec<u8>>,
    },
}

/// Every entry under a root, by its path relative to the root (bytes, `/`
/// separated, no trailing `/`).
pub type UnzipTree = BTreeMap<Vec<u8>, UnzipNode>;

/// The tree under `root`, without the entries whose relative path is one
/// of `exclude` (a directory excluded is not descended into). Modes are
/// the permission bits (`& 0o7777`); quarantine is read on macOS only.
pub fn snapshot_unzip_tree(root: &Path, exclude: &[&str]) -> UnzipTree {
    let mut t = UnzipTree::new();
    walk_unzip(root, root, exclude, &mut t);
    t
}

fn walk_unzip(root: &Path, dir: &Path, exclude: &[&str], t: &mut UnzipTree) {
    use std::os::unix::ffi::OsStrExt;
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    for p in entries {
        let rel = p
            .strip_prefix(root)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        if exclude.iter().any(|x| x.as_bytes() == rel) {
            continue;
        }
        let md = fs::symlink_metadata(&p).unwrap();
        let (mode, mtime, quarantine) = (md.mode() & 0o7777, md.mtime(), quarantine_of(&p));
        let ft = md.file_type();
        let node = if ft.is_symlink() {
            UnzipNode::Symlink {
                target: fs::read_link(&p).unwrap().as_os_str().as_bytes().to_vec(),
                quarantine,
            }
        } else if ft.is_dir() {
            UnzipNode::Dir {
                mode,
                mtime,
                quarantine,
            }
        } else {
            let bytes = if ft.is_file() {
                fs::read(&p).unwrap_or_else(|_| b"<unreadable>".to_vec())
            } else {
                b"<special>".to_vec()
            };
            UnzipNode::File {
                bytes,
                mode,
                mtime,
                quarantine,
            }
        };
        let descend = matches!(node, UnzipNode::Dir { .. });
        t.insert(rel, node);
        if descend {
            walk_unzip(root, &p, exclude, t);
        }
    }
}

/// One side of an unzip comparison: [`Run`] with the richer tree.
pub struct UnzipRun {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub tree: UnzipTree,
    /// Unix seconds when this run began (before its inputs were created).
    pub start: i64,
}

/// `raw` with every whole occurrence of the program path replaced by the
/// bare name, as [`normalise_stderr`] does, for standard output's bytes.
fn normalise_path_bytes(raw: &[u8], exe: &Path, name: &str) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let path = exe.as_os_str().as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(path) {
            let after = raw.get(i + path.len());
            if after.is_none_or(|&b| b == b':' || b.is_ascii_whitespace()) {
                out.extend_from_slice(name.as_bytes());
                i += path.len();
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

/// Run case `c` with `exe` in a fresh scratch directory: the reference
/// (`stuffr_side` false) or stuffr (true).
fn unzip_run(exe: &Path, c: &Case, stuffr_side: bool) -> UnzipRun {
    let s = Scratch::new();
    let (code, stdout, stderr, start) = spawn_case(exe, &s, c, stuffr_side);
    UnzipRun {
        code,
        stdout: normalise_path_bytes(&stdout, exe, c.name),
        stderr,
        tree: snapshot_unzip_tree(&s.0.join("work"), &[]),
        start,
    }
}

/// R2's tail of stuffr's banner for `flavour`, after `by stuffr X.Y.Z `.
fn stuffr_banner_tail(flavour: &str) -> Option<&'static str> {
    match flavour {
        "apple" => Some("(altered; original by Info-ZIP, with modifications by Apple Inc.)."),
        "ubuntu" => Some("(altered; Debian's build, original by Info-ZIP)."),
        _ => None,
    }
}

/// Every banner line becomes `<banner>`: on the reference side a line that
/// is exactly one of the references' banners, on stuffr's side (`ours`
/// the forced flavour) a line holding `, by stuffr X.Y.Z (altered; ` whose
/// tail names that flavour's origin (Apple Inc. or Debian), so another
/// flavour's banner, or text around a banner, still differs.
fn mask_unzip_banners(text: &[u8], ours: Option<&str>) -> Vec<u8> {
    let stuffr = format!(", by stuffr {} (altered; ", env!("CARGO_PKG_VERSION"));
    let marker = match ours {
        Some("apple") => Some("Apple Inc."),
        Some("ubuntu") => Some("Debian"),
        _ => None,
    };
    let mut out = Vec::with_capacity(text.len());
    for line in text.split_inclusive(|&b| b == b'\n') {
        let (body, nl) = match line.strip_suffix(b"\n") {
            Some(b) => (b, &b"\n"[..]),
            None => (line, &b""[..]),
        };
        let s = String::from_utf8_lossy(body);
        let banner = match marker {
            None => [
                APPLE_UNZIP_BANNER,
                UBUNTU_UNZIP_BANNER,
                ZIPINFO_BANNER,
                FUNZIP_BANNER,
            ]
            .contains(&s.as_ref()),
            Some(m) => s
                .split_once(&stuffr)
                .is_some_and(|(_, tail)| tail.ends_with(").") && tail.contains(m)),
        };
        out.extend_from_slice(if banner { b"<banner>" } else { body });
        out.extend_from_slice(nl);
    }
    out
}

fn node_kind(n: &UnzipNode) -> &'static str {
    match n {
        UnzipNode::File { .. } => "file",
        UnzipNode::Dir { .. } => "directory",
        UnzipNode::Symlink { .. } => "symlink",
    }
}

/// Every difference between the reference's run `r` and stuffr's `s` of
/// case `c`, one line each: exit code, standard output, standard error
/// (both with banners masked, see [`mask_unzip_banners`]), and per tree
/// entry presence, kind, bytes, mode, mtime (equal, or both created during
/// their own run), link target and quarantine. Empty when they agree.
pub fn unzip_differences(c: &Case, r: &UnzipRun, s: &UnzipRun) -> Vec<String> {
    let mut d = Vec::new();
    if r.code != s.code {
        d.push(format!(
            "exit code: reference {} vs stuffr {}",
            r.code, s.code
        ));
    }
    let (ro, so) = (
        mask_unzip_banners(&r.stdout, None),
        mask_unzip_banners(&s.stdout, c.unzip_flavour),
    );
    if ro != so {
        d.push(format!(
            "stdout differs ({}):\n  reference: {:?}\n  stuffr:    {:?}",
            first_diff(&ro, &so),
            String::from_utf8_lossy(&ro),
            String::from_utf8_lossy(&so)
        ));
    }
    let (re, se) = (
        mask_unzip_banners(r.stderr.as_bytes(), None),
        mask_unzip_banners(s.stderr.as_bytes(), c.unzip_flavour),
    );
    if re != se {
        d.push(format!(
            "stderr differs:\n  reference: {:?}\n  stuffr:    {:?}",
            String::from_utf8_lossy(&re),
            String::from_utf8_lossy(&se)
        ));
    }
    let now = now_secs();
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let names: std::collections::BTreeSet<&Vec<u8>> = r.tree.keys().chain(s.tree.keys()).collect();
    for key in names {
        let n = lossy(key);
        let (a, b) = match (r.tree.get(key), s.tree.get(key)) {
            (Some(a), Some(b)) => (a, b),
            (Some(a), None) => {
                d.push(format!(
                    "tree: {n} ({}) exists in the reference only",
                    node_kind(a)
                ));
                continue;
            }
            (None, Some(b)) => {
                d.push(format!(
                    "tree: {n} ({}) exists in stuffr only",
                    node_kind(b)
                ));
                continue;
            }
            (None, None) => unreachable!(),
        };
        let times = |rt: i64, st: i64, d: &mut Vec<String>| {
            if !mtime_ok(rt, r.start, st, s.start, now) {
                d.push(format!("tree: {n} mtime reference {rt} vs stuffr {st}"));
            }
        };
        let (rq, sq) = match (a, b) {
            (
                UnzipNode::File {
                    bytes: rb,
                    mode: rm,
                    mtime: rt,
                    quarantine: rq,
                },
                UnzipNode::File {
                    bytes: sb,
                    mode: sm,
                    mtime: st,
                    quarantine: sq,
                },
            ) => {
                if rb != sb {
                    d.push(format!(
                        "tree: {n} bytes differ ({}):\n  reference: {}\n  stuffr:    {}",
                        first_diff(rb, sb),
                        describe_bytes(rb),
                        describe_bytes(sb)
                    ));
                }
                if rm != sm {
                    d.push(format!("tree: {n} mode reference {rm:o} vs stuffr {sm:o}"));
                }
                times(*rt, *st, &mut d);
                (rq, sq)
            }
            (
                UnzipNode::Dir {
                    mode: rm,
                    mtime: rt,
                    quarantine: rq,
                },
                UnzipNode::Dir {
                    mode: sm,
                    mtime: st,
                    quarantine: sq,
                },
            ) => {
                if rm != sm {
                    d.push(format!("tree: {n} mode reference {rm:o} vs stuffr {sm:o}"));
                }
                times(*rt, *st, &mut d);
                (rq, sq)
            }
            (
                UnzipNode::Symlink {
                    target: rl,
                    quarantine: rq,
                },
                UnzipNode::Symlink {
                    target: sl,
                    quarantine: sq,
                },
            ) => {
                if rl != sl {
                    d.push(format!(
                        "tree: {n} link target reference {:?} vs stuffr {:?}",
                        lossy(rl),
                        lossy(sl)
                    ));
                }
                (rq, sq)
            }
            _ => {
                d.push(format!(
                    "tree: {n} is a {} in the reference, a {} in stuffr",
                    node_kind(a),
                    node_kind(b)
                ));
                continue;
            }
        };
        if rq != sq {
            d.push(format!(
                "tree: {n} quarantine reference {:?} vs stuffr {:?}",
                rq.as_deref().map(lossy),
                sq.as_deref().map(lossy)
            ));
        }
    }
    d
}

/// R11's note for an Apple run whose reference is not the recorded build:
/// `installed` is the installed `unzip -v` ([`apple_unzip_identity`], or a
/// test's own text). `None` when it is absent or is
/// [`APPLE_UNZIP_IDENTITY`]; otherwise a header naming the `-v` lines only
/// the recorded build has and only the installed one has, and the prefix
/// every difference then carries (`[apple drift?] `): the difference may be
/// that build's and not stuffr's.
pub fn apple_drift_note(installed: Option<&str>) -> Option<(String, &'static str)> {
    let id = installed.filter(|id| *id != APPLE_UNZIP_IDENTITY)?;
    let recorded: Vec<&str> = APPLE_UNZIP_IDENTITY.lines().collect();
    let installed: Vec<&str> = id.lines().collect();
    let only = |a: &[&str], b: &[&str]| -> Vec<String> {
        a.iter()
            .filter(|l| !b.contains(l))
            .map(|l| format!("    {l}"))
            .collect()
    };
    Some((
        format!(
            "[the installed /usr/bin/unzip is not the build this suite was verified \
             against (R11)]\n  recorded -v only:\n{}\n  installed -v only:\n{}\n",
            only(&recorded, &installed).join("\n"),
            only(&installed, &recorded).join("\n")
        ),
        "[apple drift?] ",
    ))
}

/// Panic listing every [`unzip_differences`] of `r` (reference) and `s`
/// (stuffr), if any, opened and prefixed by [`apple_drift_note`] when the
/// installed Apple reference is not the recorded build (R11).
pub fn compare_unzip(c: &Case, r: &UnzipRun, s: &UnzipRun) {
    let d = unzip_differences(c, r, s);
    if d.is_empty() {
        return;
    }
    let (head, prefix) = apple_drift_note(apple_unzip_identity()).unwrap_or_default();
    panic!(
        "{head}{} {:?}: stuffr differs from the reference in {} way(s):\n{}",
        c.name,
        c.args,
        d.len(),
        d.iter()
            .map(|x| format!(" - {prefix}{x}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Run `c` under the reference (`unzip_dir()/<c.name>`) and under stuffr
/// ([`stuffr_as`]'s link named `c.name`, given `c.unzip_flavour`), each in
/// its own scratch directory, then [`compare_unzip`] them: exit code,
/// standard output, standard error and the whole work tree. False when
/// there is no reference (a skip; a panic under `CI`), so it can be
/// [`run_group`]'s `one`.
pub fn assert_same_unzip(c: &Case) -> bool {
    let Some(dir) = unzip_dir() else {
        return false;
    };
    let exe = Path::new(dir).join(c.name);
    if !require_reference(&exe) {
        return false;
    }
    let r = unzip_run(&exe, c, false);
    let ours = stuffr_unzip(c);
    compare_unzip(c, &r, &ours);
    true
}

/// stuffr's run of `c` alone, through a link named `c.name` (in
/// `c.unzip_flavour`), as [`assert_same_unzip`] makes it: for the rulings
/// on upstream undefined behaviour, which have no reference to compare.
pub fn stuffr_unzip(c: &Case) -> UnzipRun {
    let s = Scratch::new();
    let bin = s.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let link = bin.join(c.name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    unzip_run(&link, c, true)
}

/// The reference's run of `c` alone, as [`assert_same_unzip`] makes it
/// (`None` without a reference): for the recorded tables.
pub fn unzip_reference(c: &Case) -> Option<UnzipRun> {
    let dir = unzip_dir()?;
    let exe = Path::new(dir).join(c.name);
    require_reference(&exe).then(|| unzip_run(&exe, c, false))
}

/// One byte of the CRC-32 that traditional zip encryption updates its keys
/// with (APPNOTE 6.1.5: polynomial 0xEDB88320, no pre- or post-inversion).
fn crc32_byte(crc: u32, b: u8) -> u32 {
    let mut c = (crc ^ u32::from(b)) & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            0xedb8_8320 ^ (c >> 1)
        } else {
            c >> 1
        };
    }
    c ^ (crc >> 8)
}

/// `body` (an entry's data as stored, after compression) encrypted with
/// traditional PKWARE encryption (APPNOTE 6.1) under `password`, after the
/// 12-byte header whose last byte is `check` (the CRC's high byte, or the
/// DOS time's high byte under flag bit 3). The other 11 header bytes are
/// fixed, so the archive is deterministic. Store it with flag bit 0 and
/// `stored_data`.
pub fn zipcrypto(password: &[u8], check: u8, body: &[u8]) -> Vec<u8> {
    let mut k = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    let update = |k: &mut [u32; 3], p: u8| {
        k[0] = crc32_byte(k[0], p);
        k[1] = k[1]
            .wrapping_add(k[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        k[2] = crc32_byte(k[2], (k[1] >> 24) as u8);
    };
    for &p in password {
        update(&mut k, p);
    }
    let mut plain = b"stuffr-hdr!".to_vec();
    plain.push(check);
    plain.extend_from_slice(body);
    plain
        .into_iter()
        .map(|p| {
            let t = (k[2] | 2) & 0xffff;
            let c = p ^ ((t.wrapping_mul(t ^ 1) >> 8) & 0xff) as u8;
            update(&mut k, p);
            c
        })
        .collect()
}
