//! The zip family's part of the differential harness (0.19.0 Task 1): the
//! reference lookup, the input tree ([`ZipTree`]), the comparison
//! ([`assert_same_zip`]) and the encrypted-archive check
//! ([`decrypt_equal`]). Re-exported by `compat_harness`, so suites call it
//! as `compat_harness::...`.
//!
//! The measurements behind every rule here are in
//! `~/Development/Thomas/superpowers/stuffr/upstream/zip-measurements.md`.

use super::unzip::{ZipKeys, mask_compiled_with, mask_work};
use super::*;

/// The Ubuntu reference: apt's `zip` on ubuntu 24.04 (`dpkg-query -W -f
/// '${Version}' zip`).
pub const UBUNTU_ZIP_VERSION: &str = "3.0-13ubuntu0.2";

/// The `-v` banner of each Apple program (`zip`, `zipcloak`, `zipnote`,
/// `zipsplit`): the line that names it. stuffr's own names stuffr instead
/// (the spec's banner deviation); [`mask_zip_banners`] masks both.
pub const APPLE_ZIP_BANNERS: [&str; 4] = [
    "This is Zip 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.",
    "This is ZipCloak 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.",
    "This is ZipNote 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.",
    "This is ZipSplit 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.",
];

/// The Ubuntu programs' `-v` banners (upstream's text).
pub const UBUNTU_ZIP_BANNERS: [&str; 4] = [
    "This is Zip 3.0 (July 5th 2008), by Info-ZIP.",
    "This is ZipCloak 3.0 (July 5th 2008), by Info-ZIP.",
    "This is ZipNote 3.0 (July 5th 2008), by Info-ZIP.",
    "This is ZipSplit 3.0 (July 5th 2008), by Info-ZIP.",
];

/// The line of each program's help that names it (`zip -h`, `zipcloak
/// -h`, ...), the same in both flavours.
pub const ZIP_HELP_HEADERS: [&str; 4] = [
    "Zip 3.0 (July 5th 2008). Usage:",
    "ZipCloak 3.0 (July 5th 2008)",
    "ZipNote 3.0 (July 5th 2008)",
    "ZipSplit 3.0 (July 5th 2008)",
];

/// The flavour whose reference this platform has: `apple` on macOS and
/// the BSDs, `ubuntu` elsewhere (the family's own default).
pub fn platform_zip_flavour() -> &'static str {
    platform_unzip_flavour()
}

/// The installed apt `zip` package's version, `None` without `dpkg-query`
/// or the package.
pub fn ubuntu_zip_version() -> Option<String> {
    let out = output(
        Command::new("dpkg-query")
            .args(["-W", "-f", "${Version}", "zip"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null()),
    )
    .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The directory of the platform's zip reference (`zip`, `zipcloak`,
/// `zipnote`, `zipsplit`): `/usr/bin` on macOS (Apple's build), and
/// `/usr/bin` on Linux only when the apt package is [`UBUNTU_ZIP_VERSION`]
/// (`make compat-ubuntu` and CI's ubuntu-24.04 have it). Elsewhere there
/// is none.
///
/// `None`: a skip with a note locally, a panic under `CI` (the rule of
/// [`require_reference`]), so a suite cannot pass vacuously.
pub fn zip_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Result<&'static str, String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        if !Path::new("/usr/bin/zip").is_file() {
            return Err("there is no /usr/bin/zip".to_owned());
        }
        if cfg!(target_os = "macos") {
            Ok("/usr/bin")
        } else if cfg!(target_os = "linux") {
            match ubuntu_zip_version() {
                Some(v) if v == UBUNTU_ZIP_VERSION => Ok("/usr/bin"),
                Some(v) => Err(format!(
                    "the apt zip is {v}, not {UBUNTU_ZIP_VERSION} (`make compat-ubuntu` has it)"
                )),
                None => Err("/usr/bin/zip is not apt's zip package".to_owned()),
            }
        } else {
            Err("this platform has no zip reference".to_owned())
        }
    });
    match found {
        Ok(d) => Some(d),
        Err(why) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no zip reference: {why}"
            );
            eprintln!("skipped: no zip reference ({why})");
            None
        }
    }
}

// ---- The input tree ----

/// What one [`ZipItem`] is.
#[derive(Clone, Debug, PartialEq)]
pub enum ZipNode {
    File {
        bytes: Vec<u8>,
        mode: u32,
    },
    Dir {
        mode: u32,
    },
    /// Its own times are set too (`lutimes`): `zip -y` stores the link's.
    Symlink {
        target: Vec<u8>,
    },
    /// A named pipe (zip skips it without `-FI`).
    Fifo {
        mode: u32,
    },
}

/// One path of a [`ZipTree`], relative to the work directory (bytes, `/`
/// separated), with its node and pinned times.
#[derive(Clone, Debug, PartialEq)]
pub struct ZipItem {
    pub path: Vec<u8>,
    pub node: ZipNode,
    pub mtime: i64,
    /// zip stores the access time too (the local `UT` field), so it is
    /// pinned like the modification time.
    pub atime: i64,
}

/// A zip case's input tree: what both sides get in their work directory,
/// identical in bytes, modes, mtimes and atimes (all [`INPUT_MTIME`]
/// unless set), directories and symlinks. A parent directory not listed is
/// made 0755 and pinned too, so `zip -r` sees the same tree on both sides.
/// The owner is the user running the tests, the same on both sides.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ZipTree {
    pub items: Vec<ZipItem>,
}

impl ZipTree {
    pub fn new() -> Self {
        ZipTree::default()
    }

    /// The measurement record's standard tree: `a.txt` (`hello\n`),
    /// `b.txt` (50 lines, 2240 bytes, deflates), the directory `d` and
    /// `d/c.txt` (`c\n`); files 0644, directories 0755, every time
    /// [`INPUT_MTIME`].
    pub fn standard() -> Self {
        let mut b = Vec::new();
        for i in 0..50 {
            b.extend_from_slice(
                format!("line {i} of the b file, some text to compress\n").as_bytes(),
            );
        }
        ZipTree::new()
            .file("a.txt", b"hello\n")
            .file("b.txt", b)
            .dir("d")
            .file("d/c.txt", b"c\n")
    }

    fn push(mut self, path: &[u8], node: ZipNode) -> Self {
        self.items.retain(|i| i.path != path);
        self.items.push(ZipItem {
            path: path.to_vec(),
            node,
            mtime: INPUT_MTIME as i64,
            atime: INPUT_MTIME as i64,
        });
        self
    }

    /// A regular file, mode 0644.
    pub fn file(self, path: &str, bytes: impl AsRef<[u8]>) -> Self {
        self.file_mode(path, bytes, 0o644)
    }

    pub fn file_mode(self, path: &str, bytes: impl AsRef<[u8]>, mode: u32) -> Self {
        self.file_at(path.as_bytes(), bytes, mode)
    }

    /// A regular file whose name is any bytes (a high byte, a newline).
    pub fn file_at(self, path: &[u8], bytes: impl AsRef<[u8]>, mode: u32) -> Self {
        let bytes = bytes.as_ref().to_vec();
        self.push(path, ZipNode::File { bytes, mode })
    }

    /// A directory, mode 0755.
    pub fn dir(self, path: &str) -> Self {
        self.dir_mode(path, 0o755)
    }

    pub fn dir_mode(self, path: &str, mode: u32) -> Self {
        self.push(path.as_bytes(), ZipNode::Dir { mode })
    }

    pub fn symlink(self, path: &str, target: &str) -> Self {
        let target = target.as_bytes().to_vec();
        self.push(path.as_bytes(), ZipNode::Symlink { target })
    }

    pub fn fifo(self, path: &str) -> Self {
        self.push(path.as_bytes(), ZipNode::Fifo { mode: 0o644 })
    }

    /// The times of the item at `path` (which must be listed).
    pub fn times(mut self, path: &str, mtime: i64, atime: i64) -> Self {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.path == path.as_bytes())
            .unwrap_or_else(|| panic!("ZipTree::times: {path} is not in the tree"));
        item.mtime = mtime;
        item.atime = atime;
        self
    }

    /// The items with every unlisted parent directory added (0755, pinned).
    fn complete(&self) -> Vec<ZipItem> {
        let mut items = self.items.clone();
        let mut parents = Vec::new();
        for i in &self.items {
            let mut p = i.path.as_slice();
            while let Some(cut) = p.iter().rposition(|&b| b == b'/') {
                p = &p[..cut];
                if !p.is_empty() && !items.iter().any(|x| x.path == p) && !parents.contains(&p) {
                    parents.push(p);
                }
            }
        }
        for p in parents {
            items.push(ZipItem {
                path: p.to_vec(),
                node: ZipNode::Dir { mode: 0o755 },
                mtime: INPUT_MTIME as i64,
                atime: INPUT_MTIME as i64,
            });
        }
        items
    }

    /// Make the tree under `dir` (which exists): directories, files,
    /// symlinks and FIFOs, then the files' modes, then every item's times
    /// deepest first (a directory's after its entries are made, the link's
    /// own for a symlink), then the directories' modes deepest first (a
    /// directory without search permission is made last).
    pub fn materialise(&self, dir: &Path) {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let mut items = self.complete();
        items.sort_by(|a, b| a.path.cmp(&b.path));
        let full = |p: &[u8]| dir.join(std::ffi::OsStr::from_bytes(p));
        for i in &items {
            let p = full(&i.path);
            match &i.node {
                ZipNode::Dir { .. } => fs::create_dir_all(&p).unwrap(),
                ZipNode::File { bytes, .. } => fs::write(&p, bytes).unwrap(),
                ZipNode::Symlink { target } => {
                    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target), &p).unwrap()
                }
                ZipNode::Fifo { .. } => {
                    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
                    // SAFETY: a NUL-terminated path that lives across the call.
                    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
                    assert_eq!(rc, 0, "mkfifo {p:?}: {}", std::io::Error::last_os_error());
                }
            }
        }
        for i in &items {
            if let ZipNode::File { mode, .. } | ZipNode::Fifo { mode } = i.node {
                fs::set_permissions(full(&i.path), fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        let depth = |i: &ZipItem| i.path.iter().filter(|&&b| b == b'/').count();
        items.sort_by_key(|i| std::cmp::Reverse(depth(i)));
        for i in &items {
            set_times_nofollow(&full(&i.path), i.mtime, i.atime);
        }
        for i in &items {
            if let ZipNode::Dir { mode } = i.node {
                fs::set_permissions(full(&i.path), fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }
}

/// `utimensat(AT_SYMLINK_NOFOLLOW)`: the times of `p` itself, a symlink's
/// own included.
fn set_times_nofollow(p: &Path, mtime: i64, atime: i64) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let ts = |s: i64| libc::timespec {
        tv_sec: s as libc::time_t,
        tv_nsec: 0,
    };
    let times = [ts(atime), ts(mtime)];
    // SAFETY: a NUL-terminated path and two timespecs, all live across the
    // call.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(
        rc,
        0,
        "utimensat {p:?}: {}",
        std::io::Error::last_os_error()
    );
}

/// A case for the zip family: `name` (`zip`, `zipcloak`, `zipnote`,
/// `zipsplit`) with `args` over `tree`, standard input `/dev/null`,
/// `TZ=UTC`, `LANG=C`, and stuffr forced to this platform's flavour
/// ([`platform_zip_flavour`]). A suite of the other flavour sets
/// `zip_flavour` itself; `stdin`, `env`, `tty_ctl` are set on the result.
pub fn zip_case(name: &'static str, args: &[&'static str], tree: ZipTree) -> Case<'static> {
    Case {
        name,
        args: args.to_vec(),
        files: vec![],
        stdin: None,
        tty_stdin: false,
        tty_stdout: false,
        env: vec![],
        compare_output_bytes: true,
        expect_stdout_plain: None,
        setup: None,
        // Unused: zip's outputs are compared byte for byte, never decoded.
        roundtrip: Roundtrip::Exact,
        tz: None,
        unzip_flavour: None,
        tty_ctl: false,
        tty_signal: None,
        zip_flavour: Some(platform_zip_flavour()),
        zip_tree: Some(tree),
    }
}

// ---- Masks ----

/// Every program-naming line becomes `<banner>` (a `-v` banner) or
/// `<usage-banner>` (a help header). On the reference side (`ours` None) a
/// line that is exactly one of [`APPLE_ZIP_BANNERS`], [`UBUNTU_ZIP_BANNERS`]
/// or [`ZIP_HELP_HEADERS`]. On stuffr's side (`ours` the forced flavour) a
/// line `HEAD, by stuffr X.Y.Z (altered; TEXT)REST` where `HEAD` and `REST`
/// are a reference line's (the text before its `, by ` and after it: `.`
/// for a banner, `. Usage:` for zip's help header, nothing for the
/// helpers'), and `TEXT` names the flavour's origin (`Apple Inc.`;
/// `Debian` or `Ubuntu`). Text around such a line, another flavour's
/// origin or another version still differs.
pub fn mask_zip_banners(text: &[u8], ours: Option<&str>) -> Vec<u8> {
    let marker: &[&str] = match ours {
        Some("apple") => &["Apple Inc."],
        Some("ubuntu") => &["Debian", "Ubuntu"],
        _ => &[],
    };
    let stuffr = format!(", by stuffr {} (altered; ", env!("CARGO_PKG_VERSION"));
    // (head, rest, label) of every reference line
    let mut shapes: Vec<(&str, &str, &str)> = Vec::new();
    for b in APPLE_ZIP_BANNERS.iter().chain(UBUNTU_ZIP_BANNERS.iter()) {
        let head = b.split_once(", by ").map_or(*b, |(h, _)| h);
        shapes.push((head, ".", "<banner>"));
    }
    for h in ZIP_HELP_HEADERS {
        let (head, rest) = h
            .split_once(". Usage:")
            .map_or((h, ""), |(a, _)| (a, ". Usage:"));
        shapes.push((head, rest, "<usage-banner>"));
    }
    let mut out = Vec::with_capacity(text.len());
    for line in text.split_inclusive(|&b| b == b'\n') {
        let (body, nl) = match line.strip_suffix(b"\n") {
            Some(b) => (b, &b"\n"[..]),
            None => (line, &b""[..]),
        };
        let s = String::from_utf8_lossy(body);
        let label = if ours.is_none() {
            if APPLE_ZIP_BANNERS.contains(&s.as_ref()) || UBUNTU_ZIP_BANNERS.contains(&s.as_ref()) {
                Some("<banner>")
            } else if ZIP_HELP_HEADERS.contains(&s.as_ref()) {
                Some("<usage-banner>")
            } else {
                None
            }
        } else {
            s.split_once(&stuffr).and_then(|(head, tail)| {
                let close = tail.rfind(')')?;
                let (what, rest) = (&tail[..close], &tail[close + 1..]);
                if !marker.iter().any(|m| what.contains(m)) {
                    return None;
                }
                shapes
                    .iter()
                    .find(|(h, r, _)| *h == head && *r == rest)
                    .map(|(_, _, l)| *l)
            })
        };
        match label {
            Some(l) => out.extend_from_slice(l.as_bytes()),
            None => out.extend_from_slice(body),
        }
        out.extend_from_slice(nl);
    }
    out
}

/// A name `zip` gives its temporary files (`mkstemp("ziXXXXXX")`), one
/// path component: `zi` and six letters or digits, not a program name.
fn is_temp_name(b: &[u8]) -> bool {
    b.len() == 8
        && b.starts_with(b"zi")
        && b[2..].iter().all(u8::is_ascii_alphanumeric)
        && b != b"zipsplit"
        && b != b"zipcloak"
}

/// Every temporary file name (`zi` + six random characters, a whole path
/// component: after the start, a space, `(`, `/` or `[`, before the end,
/// a space, `)`, `]` or a newline) becomes `zi??????`: two runs never pick
/// the same, so messages that name one (`Temporary file failure
/// (ziAb12Cd)`) and test commands given one differ by it alone.
pub fn mask_temp_names(text: &[u8]) -> Vec<u8> {
    let mut out = text.to_vec();
    let mut i = 0;
    while i + 8 <= out.len() {
        let before_ok = i == 0 || matches!(out[i - 1], b' ' | b'(' | b'/' | b'[' | b'\t' | b'\n');
        let after_ok =
            i + 8 == out.len() || matches!(out[i + 8], b' ' | b')' | b']' | b'\n' | b'\'');
        if before_ok && after_ok && is_temp_name(&out[i..i + 8]) {
            out[i + 2..i + 8].copy_from_slice(b"??????");
            i += 8;
        } else {
            i += 1;
        }
    }
    out
}

/// [`mask_zip_banners`], [`mask_temp_names`], then for the Apple flavour
/// the `Compiled with ... on <date>.` line of `-v` (another macOS ships
/// another build, as for unzip's P41). An output that [`looks_like_zip`]
/// is an archive, not text: returned unchanged.
pub fn mask_zip_output(text: &[u8], ours: Option<&str>, apple: bool) -> Vec<u8> {
    if looks_like_zip(text) {
        return text.to_vec();
    }
    let masked = mask_temp_names(&mask_zip_banners(text, ours));
    if apple {
        mask_compiled_with(&masked)
    } else {
        masked
    }
}

// ---- Archive bytes ----

/// Unix seconds of an MS-DOS date and time read as UTC (both sides run
/// with `TZ=UTC`); `None` for an impossible one.
fn dos_to_unix(time: u16, date: u16) -> Option<i64> {
    let (y, m, d) = (
        1980 + i64::from(date >> 9),
        i64::from((date >> 5) & 15),
        i64::from(date & 31),
    );
    let (hh, mm, ss) = (
        i64::from(time >> 11),
        i64::from((time >> 5) & 63),
        i64::from(time & 31) * 2,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // days from civil (Howard Hinnant's algorithm)
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Whether `b` looks like a zip archive: a local header or an end record
/// at the start.
pub fn looks_like_zip(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") || b.starts_with(b"PK\x07\x08")
}

/// The offsets of the MS-DOS time and date in every local (`+10`) and
/// central (`+12`) header signature of `b`.
fn dos_time_offsets(b: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    for i in 0..b.len().saturating_sub(3) {
        if b[i] == b'P' && b[i + 1] == b'K' {
            let at = match (b[i + 2], b[i + 3]) {
                (3, 4) => i + 10,
                (1, 2) => i + 12,
                _ => continue,
            };
            if at + 4 <= b.len() {
                v.push(at);
            }
        }
    }
    v
}

/// The "now" times of two runs' archives made equal: zip stores the time it
/// ran for standard input (`-`) and other entries without a file time. At
/// every header offset the two have in common, an MS-DOS time and date
/// that differ, each within its own run's window (`[start - 2, end + 2]`:
/// two-second resolution), become the reference's in `s`. Any other
/// difference is left for the comparison.
pub fn mask_now_times(r: &[u8], r_window: (i64, i64), s: &mut [u8], s_window: (i64, i64)) {
    let in_window = |b: &[u8], at: usize, (start, end): (i64, i64)| {
        let time = u16::from_le_bytes([b[at], b[at + 1]]);
        let date = u16::from_le_bytes([b[at + 2], b[at + 3]]);
        dos_to_unix(time, date).is_some_and(|t| t >= start - 2 && t <= end + 2)
    };
    let theirs = dos_time_offsets(s);
    for at in dos_time_offsets(r) {
        if theirs.contains(&at)
            && r[at..at + 4] != s[at..at + 4]
            && in_window(r, at, r_window)
            && in_window(s, at, s_window)
        {
            s[at..at + 4].copy_from_slice(&r[at..at + 4]);
        }
    }
}

/// Where offset `at` of archive `b` lies: the last record signature at or
/// before it, by kind, and the distance from it.
pub fn zip_region(b: &[u8], at: usize) -> String {
    let kinds: [(&[u8], &str); 6] = [
        (b"PK\x03\x04", "local header"),
        (b"PK\x01\x02", "central header"),
        (b"PK\x05\x06", "end record"),
        (b"PK\x06\x06", "Zip64 end record"),
        (b"PK\x06\x07", "Zip64 locator"),
        (b"PK\x07\x08", "data descriptor"),
    ];
    let end = at.min(b.len().saturating_sub(4));
    for i in (0..=end).rev() {
        if let Some((_, k)) = kinds.iter().find(|(sig, _)| b[i..].starts_with(sig)) {
            return format!("{k} at {i}, +{}", at - i);
        }
    }
    "before any record".to_owned()
}

fn archive_name(name: &[u8]) -> bool {
    let n = String::from_utf8_lossy(name).to_ascii_lowercase();
    if n.ends_with(".zip") {
        return true;
    }
    // split parts: .z01, .z02, ... (two or more digits)
    n.rsplit_once(".z")
        .is_some_and(|(_, d)| d.len() >= 2 && d.bytes().all(|c| c.is_ascii_digit()))
}

// ---- Runs and the comparison ----

/// One side of a zip comparison.
pub struct ZipRun {
    pub code: i32,
    pub stdout: Vec<u8>,
    /// Bytes, compared byte for byte (rendered lossily only in messages).
    pub stderr: Vec<u8>,
    /// The work directory afterwards (a temporary file's name masked as
    /// `zi??????`).
    pub tree: UnzipTree,
    /// Unix seconds when this run began (before its inputs were made) and
    /// ended: the window of its "now" times.
    pub start: i64,
    pub end: i64,
    /// With [`Case::tty_ctl`]: echo and canonical mode of the controlling
    /// terminal after the run.
    pub tty_mode: Option<(bool, bool)>,
}

/// Run case `c` with `exe` in a fresh scratch directory: the reference
/// (`stuffr_side` false) or stuffr (true). The work directory's path (as
/// given and real) reads `<work>` in both streams and in symlink targets.
fn zip_run(exe: &Path, c: &Case, stuffr_side: bool) -> ZipRun {
    use std::os::unix::ffi::OsStrExt;
    let s = Scratch::new();
    let Spawned {
        code,
        stdout,
        stderr_bytes,
        start,
        tty_mode,
        ..
    } = spawn_case(exe, &s, c, stuffr_side);
    let end = now_secs();
    let work = s.0.join("work");
    let mut dirs = vec![work.as_os_str().as_bytes().to_vec()];
    if let Ok(real) = fs::canonicalize(&work) {
        dirs.insert(0, real.as_os_str().as_bytes().to_vec());
    }
    let mut tree = UnzipTree::new();
    for (k, mut node) in snapshot_unzip_tree(&work, &[]) {
        if let UnzipNode::Symlink { target, .. } = &mut node {
            *target = mask_work(target, &dirs);
        }
        let mut key = k.clone();
        let base = key.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
        if is_temp_name(&key[base..]) {
            key[base + 2..].copy_from_slice(b"??????");
        }
        tree.insert(key, node);
    }
    // `-sc` shows argv[0] in quotes, as invoked: by path, here
    let quoted = |b: &[u8]| -> Vec<u8> {
        let from = [&b"'"[..], exe.as_os_str().as_bytes(), &b"'"[..]].concat();
        let to = [&b"'"[..], c.name.as_bytes(), &b"'"[..]].concat();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i..].starts_with(&from) {
                out.extend_from_slice(&to);
                i += from.len();
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    };
    ZipRun {
        code,
        stdout: mask_work(&quoted(&normalise_path_bytes(&stdout, exe, c.name)), &dirs),
        stderr: mask_work(&quoted(&stderr_bytes), &dirs),
        tree,
        start,
        end,
        tty_mode,
    }
}

/// Every difference between the reference's run `r` and stuffr's `s` of
/// case `c`, one line each, in this order: exit code; standard output and
/// standard error ([`mask_zip_output`]; a standard output that is an
/// archive also through [`mask_now_times`]); every archive in the tree
/// (`*.zip`, split parts `*.zNN`, or a file starting like one), byte for
/// byte after [`mask_now_times`], naming the first differing offset and its
/// record; then the rest of the tree (presence, kind, bytes, mode, mtime,
/// link target), as `unzip_differences` compares it. Empty when they agree.
pub fn zip_differences(c: &Case, r: &ZipRun, s: &ZipRun) -> Vec<String> {
    let mut d = Vec::new();
    if r.code != s.code {
        d.push(format!(
            "exit code: reference {} vs stuffr {}",
            r.code, s.code
        ));
    }
    let apple = c.zip_flavour == Some("apple");
    let (rw, sw) = ((r.start, r.end), (s.start, s.end));
    let ro = mask_zip_output(&r.stdout, None, apple);
    let mut so = mask_zip_output(&s.stdout, c.zip_flavour, apple);
    if looks_like_zip(&ro) && looks_like_zip(&so) {
        mask_now_times(&ro, rw, &mut so, sw);
    }
    if ro != so {
        let what = if looks_like_zip(&ro) {
            format!(
                "{}, {}",
                first_diff(&ro, &so),
                zip_region(&ro, diff_at(&ro, &so))
            )
        } else {
            first_diff(&ro, &so)
        };
        d.push(format!(
            "stdout differs ({what}):\n  reference: {:?}\n  stuffr:    {:?}",
            String::from_utf8_lossy(&ro),
            String::from_utf8_lossy(&so)
        ));
    }
    let (re, se) = (
        mask_zip_output(&r.stderr, None, apple),
        mask_zip_output(&s.stderr, c.zip_flavour, apple),
    );
    if re != se {
        d.push(format!(
            "stderr differs:\n  reference: {:?}\n  stuffr:    {:?}",
            String::from_utf8_lossy(&re),
            String::from_utf8_lossy(&se)
        ));
    }
    // Archives first, then the rest of the tree with them made equal.
    let (mut rt, mut st) = (r.tree.clone(), s.tree.clone());
    for (key, rn) in r.tree.iter() {
        let (UnzipNode::File { bytes: rb, .. }, Some(UnzipNode::File { bytes: sb, .. })) =
            (rn, s.tree.get(key))
        else {
            continue;
        };
        if !(archive_name(key) || looks_like_zip(rb)) {
            continue;
        }
        let mut sm = sb.clone();
        mask_now_times(rb, rw, &mut sm, sw);
        if *rb != sm {
            d.push(format!(
                "archive {} differs ({}, {}; reference {} bytes, stuffr {}):\n  reference: {}\n  stuffr:    {}",
                String::from_utf8_lossy(key),
                first_diff(rb, &sm),
                zip_region(rb, diff_at(rb, &sm)),
                rb.len(),
                sm.len(),
                describe_bytes(rb),
                describe_bytes(&sm)
            ));
        }
        // compared: the rest of the comparison sees them equal
        if let Some(UnzipNode::File { bytes, .. }) = rt.get_mut(key) {
            bytes.clear();
        }
        if let Some(UnzipNode::File { bytes, .. }) = st.get_mut(key) {
            bytes.clear();
        }
    }
    let tree_only = |tree: UnzipTree, start: i64, tty_mode| UnzipRun {
        code: 0,
        stdout: Vec::new(),
        stderr: String::new(),
        tree,
        start,
        tty_mode,
    };
    d.extend(unzip_differences(
        c,
        &tree_only(rt, r.start, r.tty_mode),
        &tree_only(st, s.start, s.tty_mode),
    ));
    d
}

/// The first offset where `a` and `b` differ (the shorter length when one
/// is a prefix of the other).
fn diff_at(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

/// Panic listing every [`zip_differences`] of `r` (reference) and `s`
/// (stuffr), if any.
pub fn compare_zip(c: &Case, r: &ZipRun, s: &ZipRun) {
    let d = zip_differences(c, r, s);
    if d.is_empty() {
        return;
    }
    panic!(
        "{} {:?}: stuffr differs from the reference in {} way(s):\n{}",
        c.name,
        c.args,
        d.len(),
        d.iter()
            .map(|x| format!(" - {x}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Run `c` under the reference (`zip_dir()/<c.name>`) and under stuffr (a
/// link named `c.name`, given `c.zip_flavour`), each in its own scratch
/// directory over the same [`ZipTree`], then [`compare_zip`] them: exit
/// code, standard output, standard error, every archive byte for byte, the
/// rest of the tree. False when there is no reference (a skip; a panic
/// under `CI`), so it can be [`run_group`]'s `one`.
pub fn assert_same_zip(c: &Case) -> bool {
    let Some(r) = zip_reference(c) else {
        return false;
    };
    let ours = stuffr_zip(c);
    compare_zip(c, &r, &ours);
    true
}

/// stuffr's run of `c` alone, through a link named `c.name` (in
/// `c.zip_flavour`), as [`assert_same_zip`] makes it: for the rulings on
/// upstream undefined behaviour, which have no reference to compare.
pub fn stuffr_zip(c: &Case) -> ZipRun {
    let (_s, link) = stuffr_link(c);
    zip_run(&link, c, true)
}

/// The reference's run of `c` alone, as [`assert_same_zip`] makes it
/// (`None` without a reference): for the recorded tables.
pub fn zip_reference(c: &Case) -> Option<ZipRun> {
    let dir = zip_dir()?;
    let exe = Path::new(dir).join(c.name);
    require_reference(&exe).then(|| zip_run(&exe, c, false))
}

// ---- Encrypted archives ----

/// `body` encrypted with traditional PKWARE encryption under `password`,
/// after the 12-byte header `head` + `check` (as zip writes it: ten random
/// bytes in zip's own header, the last two its check). Unlike
/// [`zipcrypto`], the header bytes are the caller's, so two archives that
/// differ only by them can be built.
pub fn zipcrypto_with(password: &[u8], head: [u8; 11], check: u8, body: &[u8]) -> Vec<u8> {
    let mut k = ZipKeys::new(password);
    head.iter()
        .chain(std::iter::once(&check))
        .chain(body)
        .map(|&p| k.encrypt(p))
        .collect()
}

fn le16(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .ok_or_else(|| format!("archive cut short at {at}"))
}
fn le32(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| format!("archive cut short at {at}"))
}
fn le64(b: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from(le32(b, at)?) | (u64::from(le32(b, at + 4)?) << 32))
}

/// One central-directory entry, as far as decryption needs it.
struct CdEntry {
    name: Vec<u8>,
    flags: u16,
    crc: u32,
    csize: u64,
    local: u64,
}

/// The central directory of `b`, through the end record (and the Zip64 one
/// when a field is saturated).
fn central_entries(b: &[u8]) -> Result<Vec<CdEntry>, String> {
    let eocd = (0..=b.len().saturating_sub(22))
        .rev()
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))
        .ok_or("no end record")?;
    let mut count = u64::from(le16(b, eocd + 10)?);
    let mut cd_off = u64::from(le32(b, eocd + 16)?);
    if count == 0xffff || cd_off == 0xffff_ffff {
        let loc = eocd.checked_sub(20).ok_or("no Zip64 locator")?;
        if !b[loc..].starts_with(b"PK\x06\x07") {
            return Err("no Zip64 locator".into());
        }
        let z = usize::try_from(le64(b, loc + 8)?).map_err(|e| e.to_string())?;
        if !b.get(z..).is_some_and(|x| x.starts_with(b"PK\x06\x06")) {
            return Err("no Zip64 end record".into());
        }
        count = le64(b, z + 32)?;
        cd_off = le64(b, z + 48)?;
    }
    let mut at = usize::try_from(cd_off).map_err(|e| e.to_string())?;
    let mut v = Vec::new();
    for _ in 0..count {
        if !b.get(at..).is_some_and(|x| x.starts_with(b"PK\x01\x02")) {
            return Err(format!("no central header at {at}"));
        }
        let flags = le16(b, at + 8)?;
        let crc = le32(b, at + 16)?;
        let mut csize = u64::from(le32(b, at + 20)?);
        let usize_ = le32(b, at + 24)?;
        let (n, e, k) = (
            usize::from(le16(b, at + 28)?),
            usize::from(le16(b, at + 30)?),
            usize::from(le16(b, at + 32)?),
        );
        let mut local = u64::from(le32(b, at + 42)?);
        let name = b
            .get(at + 46..at + 46 + n)
            .ok_or("central name cut short")?
            .to_vec();
        // the Zip64 extra field: the saturated fields, in order
        let extra = b
            .get(at + 46 + n..at + 46 + n + e)
            .ok_or("extra cut short")?;
        let mut i = 0;
        while i + 4 <= extra.len() {
            let (id, len) = (le16(extra, i)?, usize::from(le16(extra, i + 2)?));
            if id == 1 {
                let mut p = i + 4;
                if usize_ == 0xffff_ffff {
                    p += 8;
                }
                if csize == 0xffff_ffff {
                    csize = le64(extra, p)?;
                    p += 8;
                }
                if local == 0xffff_ffff {
                    local = le64(extra, p)?;
                }
            }
            i += 4 + len;
        }
        v.push(CdEntry {
            name,
            flags,
            crc,
            csize,
            local,
        });
        at += 46 + n + e + k;
    }
    Ok(v)
}

/// `b` with every encrypted entry's 12-byte header zeroed and its data
/// decrypted under `pw`; an error if a header's check byte (the CRC's high
/// byte, or the MS-DOS time's under flag bit 3) does not match.
fn decrypted_view(b: &[u8], pw: &[u8]) -> Result<Vec<u8>, String> {
    let mut view = b.to_vec();
    for e in central_entries(b)? {
        if e.flags & 1 == 0 {
            continue;
        }
        let lh = usize::try_from(e.local).map_err(|x| x.to_string())?;
        if !b.get(lh..).is_some_and(|x| x.starts_with(b"PK\x03\x04")) {
            return Err(format!("no local header at {lh}"));
        }
        let ds = lh + 30 + usize::from(le16(b, lh + 26)?) + usize::from(le16(b, lh + 28)?);
        let n = usize::try_from(e.csize).map_err(|x| x.to_string())?;
        let data = b.get(ds..ds + n).ok_or("encrypted data cut short")?;
        if n < 12 {
            return Err(format!(
                "{}: encrypted data shorter than its header",
                String::from_utf8_lossy(&e.name)
            ));
        }
        let mut k = ZipKeys::new(pw);
        let plain: Vec<u8> = data.iter().map(|&c| k.decrypt(c)).collect();
        let check = if e.flags & 8 != 0 {
            b[lh + 11]
        } else {
            (e.crc >> 24) as u8
        };
        if plain[11] != check {
            return Err(format!(
                "{}: the password check byte is {:#04x}, the entry wants {check:#04x}",
                String::from_utf8_lossy(&e.name),
                plain[11]
            ));
        }
        view[ds..ds + 12].fill(0);
        view[ds + 12..ds + n].copy_from_slice(&plain[12..]);
    }
    Ok(view)
}

/// Two encrypted archives agree: both decrypt under `pw` (each entry's
/// check byte holds), and with every encryption header zeroed and every
/// entry's data decrypted they are byte-identical. zip draws the ten
/// random header bytes from `rand()`, so two runs of the reference differ
/// there and only there (the spec's encryption exception).
pub fn decrypt_equal(a: &Path, b: &Path, pw: &str) -> Result<(), String> {
    let read = |p: &Path| fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let (ab, bb) = (read(a)?, read(b)?);
    let av = decrypted_view(&ab, pw.as_bytes()).map_err(|e| format!("{}: {e}", a.display()))?;
    let bv = decrypted_view(&bb, pw.as_bytes()).map_err(|e| format!("{}: {e}", b.display()))?;
    if av == bv {
        return Ok(());
    }
    Err(format!(
        "{} and {} differ outside the encryption headers ({}, {})",
        a.display(),
        b.display(),
        first_diff(&av, &bv),
        zip_region(&av, diff_at(&av, &bv))
    ))
}
