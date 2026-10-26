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

/// Every [`ZipTree`] item's access time unless set: after its
/// modification time and after the change time materialising gives it (now),
/// so a `relatime` mount never stamps it when a run reads the file (zip
/// stores the access time; two runs reading a second apart would differ).
pub const INPUT_ATIME: i64 = 2_000_000_000;

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
/// identical in bytes, modes, mtimes and atimes (all [`INPUT_MTIME`] and
/// [`INPUT_ATIME`] unless set), directories and symlinks. A parent directory not listed is
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
            atime: INPUT_ATIME,
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
                atime: INPUT_ATIME,
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
/// a space, `)`, `]`, `'`, `.` or a newline) becomes `zi??????`: two runs never pick
/// the same, so messages that name one (`Temporary file failure
/// (ziAb12Cd)`) and test commands given one differ by it alone.
pub fn mask_temp_names(text: &[u8]) -> Vec<u8> {
    let mut out = text.to_vec();
    let mut i = 0;
    while i + 8 <= out.len() {
        let before_ok = i == 0 || matches!(out[i - 1], b' ' | b'(' | b'/' | b'[' | b'\t' | b'\n');
        let after_ok =
            i + 8 == out.len() || matches!(out[i + 8], b' ' | b')' | b']' | b'\n' | b'\'' | b'.');
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
    civil_to_unix(y, m, d, hh, mm, ss)
}

/// Unix seconds of a UTC civil date and time; `None` for an impossible one.
fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> Option<i64> {
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

/// Unix seconds of an `asctime()` text (`Sun Sep 16 01:03:52 1973`, 24
/// bytes, read as UTC: both sides run with `TZ=UTC`); `None` if `b` is not
/// one.
fn asctime_to_unix(b: &[u8]) -> Option<i64> {
    const MONTHS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    if b.len() != 24 || b[3] != b' ' || b[7] != b' ' || b[10] != b' ' || b[19] != b' ' {
        return None;
    }
    let num = |x: &[u8]| -> Option<i64> { std::str::from_utf8(x).ok()?.trim_start().parse().ok() };
    let m = MONTHS.iter().position(|&n| n == &b[4..7])? as i64 + 1;
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    civil_to_unix(
        num(&b[20..24])?,
        m,
        num(&b[8..10])?,
        num(&b[11..13])?,
        num(&b[14..16])?,
        num(&b[17..19])?,
    )
}

/// The wall-clock times of two runs' text files made equal (`-lf`'s `Zip
/// log opened <asctime>` line): wherever both lines hold an `asctime()`
/// text at the same offset, each within its own run's window (`[start - 1,
/// end + 1]`), `s` takes the reference's. Any other difference is left for
/// the comparison.
pub fn mask_asctimes(r: &[u8], r_window: (i64, i64), s: &mut [u8], s_window: (i64, i64)) {
    if r.len() != s.len() {
        return;
    }
    let inside = |t: i64, (start, end): (i64, i64)| t >= start - 1 && t <= end + 1;
    let mut i = 0;
    while i + 24 <= r.len() {
        if r[i..i + 24] != s[i..i + 24]
            && let (Some(a), Some(b)) = (
                asctime_to_unix(&r[i..i + 24]),
                asctime_to_unix(&s[i..i + 24]),
            )
            && inside(a, r_window)
            && inside(b, s_window)
        {
            s[i..i + 24].copy_from_slice(&r[i..i + 24]);
            i += 24;
        } else {
            i += 1;
        }
    }
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
            // a log's `Zip log opened <now>` line
            if let Some(UnzipNode::File { bytes, .. }) = st.get_mut(key) {
                mask_asctimes(rb, rw, bytes, sw);
            }
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

/// The password of the encrypted cases ([`zip_encrypted_matrix`], the
/// pty suite).
pub const ZIP_PASSWORD: &str = "pw";

/// Every archive of a run (an archive on standard output, and each archive
/// in its tree) replaced by its [`decrypt_equal`] view under `pw`: headers
/// zeroed, data decrypted, a check byte that does not hold a panic naming
/// the side.
pub fn decrypt_zip_run(run: &mut ZipRun, pw: &str, side: &str) {
    if looks_like_zip(&run.stdout) {
        run.stdout = decrypted_view(&run.stdout, pw.as_bytes())
            .unwrap_or_else(|e| panic!("{side}'s standard output: {e}"));
    }
    for (key, node) in run.tree.iter_mut() {
        let UnzipNode::File { bytes, .. } = node else {
            continue;
        };
        if archive_name(key) || looks_like_zip(bytes) {
            *bytes = decrypted_view(bytes, pw.as_bytes())
                .unwrap_or_else(|e| panic!("{side}'s {}: {e}", String::from_utf8_lossy(key)));
        }
    }
}

/// [`assert_same_zip`] for a case whose archives are encrypted under `pw`
/// (the spec's one exception: zip's header bytes are random): both sides'
/// archives are first replaced by their decrypted views
/// ([`decrypt_zip_run`]), so every byte outside the 12-byte headers and
/// every decrypted byte is compared, and each header's check byte must
/// hold.
pub fn assert_same_zip_decrypted(c: &Case, pw: &str) -> bool {
    let Some(mut r) = zip_reference(c) else {
        return false;
    };
    let mut s = stuffr_zip(c);
    decrypt_zip_run(&mut r, pw, "reference");
    decrypt_zip_run(&mut s, pw, "stuffr");
    compare_zip(c, &r, &s);
    true
}

/// The standard tree plus `t.zip`: `entries` (name, encrypted), each
/// holding `hello\n` stored, the encrypted ones under [`ZIP_PASSWORD`] with
/// fixed header bytes (traditional PKWARE encryption through
/// [`zipcrypto`], the check the CRC's high byte): the same bytes on both
/// sides of a comparison.
pub fn with_encrypted(entries: &[(&[u8], bool)]) -> ZipTree {
    ZipTree::standard().file("t.zip", encrypted_zip(entries))
}

/// [`with_encrypted`]'s archive alone.
pub fn encrypted_zip(entries: &[(&[u8], bool)]) -> Vec<u8> {
    let plain: &[u8] = b"hello\n";
    let body = zipcrypto(ZIP_PASSWORD.as_bytes(), (crc32(plain) >> 24) as u8, plain);
    let specs: Vec<ZipEntrySpec> = entries
        .iter()
        .map(|&(n, enc)| {
            if enc {
                ZipEntrySpec {
                    flags: 1,
                    stored_data: Some(&body),
                    ..ZipEntrySpec::new(n, plain)
                }
            } else {
                ZipEntrySpec::new(n, plain)
            }
        })
        .collect();
    zip_with(&specs, b"", b"")
}

/// Task 9's matrix: archives encrypted with `-P` (stored and deflated
/// entries, every level's path, data descriptors forced or on a pipe, a
/// directory never encrypted, links, line ends, standard input, an update
/// beside plain and encrypted old entries, `-d` over encrypted ones),
/// compared with [`assert_same_zip_decrypted`] under [`ZIP_PASSWORD`].
pub fn zip_encrypted_matrix(flavour: &'static str) -> Vec<Case<'static>> {
    let tree = zip_bytes_tree();
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str], tree: &ZipTree, stdin: Option<&[u8]>| {
        let mut c = zip_case("zip", args, tree.clone());
        c.zip_flavour = Some(flavour);
        c.stdin = stdin.map(<[u8]>::to_vec);
        out.push(c);
    };
    const NAMES: [&str; 9] = [
        "a.txt", "b.txt", "d", "d/c.txt", "big.txt", "r.bin", "s.bin", "e.txt", "x.Z",
    ];
    let with = |pre: &[&'static str], archive: &'static str| -> Vec<&'static str> {
        let mut v = vec!["-P", ZIP_PASSWORD];
        v.extend_from_slice(pre);
        v.push(archive);
        v.extend_from_slice(&NAMES);
        v
    };
    for pre in [
        &[][..],
        &["-0"],
        &["-1"],
        &["-6"],
        &["-9"],
        &["-fd"],
        &["-fd", "-0"],
        &["-fz"],
        &["-l"],
        &["-X"],
        &["-v"],
        &["-q"],
        &["-n", ".txt"],
    ] {
        add(&with(pre, "t.zip"), &tree, None);
    }
    // an archive on a pipe: descriptors, nothing stored after the fact
    add(&with(&[], "-"), &tree, None);
    add(&with(&["-0"], "-"), &tree, None);
    // a directory is never encrypted; links stored as links
    add(&["-P", ZIP_PASSWORD, "-r", "t.zip", "d"], &tree, None);
    add(
        &["-P", ZIP_PASSWORD, "-y", "t.zip", "l", "a.txt"],
        &tree,
        None,
    );
    add(&["-P", ZIP_PASSWORD, "t.zip", "e.txt"], &tree, None);
    // standard input as an entry (to a file: the header rewritten)
    add(
        &["-P", ZIP_PASSWORD, "t.zip", "-"],
        &tree,
        Some(
            b"from stdin
",
        ),
    );
    // `-e` after `-P` asks; `-P` after `-e` does not
    add(&["-e", "-P", ZIP_PASSWORD, "t.zip", "a.txt"], &tree, None);
    add(&["-P", ZIP_PASSWORD, "-e", "t.zip", "a.txt"], &tree, None);
    // updates: plain old entries kept beside new encrypted ones, encrypted
    // old entries copied (with their descriptors) beside new plain ones
    let std = ZipTree::standard();
    let plain = zip_made(flavour, &std, &["t.zip", "a.txt", "b.txt"], "t.zip");
    let enc = zip_made(
        flavour,
        &std,
        &["-P", ZIP_PASSWORD, "t.zip", "a.txt", "b.txt"],
        "t.zip",
    );
    let over_plain = std.clone().file("t.zip", plain);
    let over_enc = std.clone().file("t.zip", enc);
    add(&["-P", ZIP_PASSWORD, "t.zip", "d/c.txt"], &over_plain, None);
    add(&["-P", ZIP_PASSWORD, "t.zip", "a.txt"], &over_plain, None);
    add(&["t.zip", "d/c.txt"], &over_enc, None);
    add(&["-P", ZIP_PASSWORD, "t.zip", "b.txt"], &over_enc, None);
    add(&["-d", "t.zip", "a.txt"], &over_enc, None);
    add(
        &["-P", ZIP_PASSWORD, "-g", "t.zip", "d/c.txt"],
        &over_enc,
        None,
    );
    add(
        &["-P", ZIP_PASSWORD, "--out", "o.zip", "t.zip", "d/c.txt"],
        &over_enc,
        None,
    );
    add(&["-U", "t.zip", "a.txt", "--out", "o.zip"], &over_enc, None);
    out
}

// ---- The scanning matrix (0.19.0 Task 5) ----

/// The cases of `compat_zip_apple` and `compat_zip_ubuntu`'s scanning
/// matrix: which names zip would operate on (`-sf` lists them without
/// writing), over every shape of operand, pattern, directory, link and date
/// filter, in `flavour`. Nothing in them writes an archive, so the exit
/// code, both streams and the (unchanged) tree are all there is to compare.
pub fn zip_scan_matrix(flavour: &'static str) -> Vec<Case<'static>> {
    let std_tree = ZipTree::standard;
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str], tree: ZipTree, stdin: Option<&[u8]>| {
        let mut c = zip_case("zip", args, tree);
        c.zip_flavour = Some(flavour);
        c.stdin = stdin.map(<[u8]>::to_vec);
        out.push(c);
    };
    // operands, directories and recursion
    for args in [
        &["-sf", "t.zip", "a.txt"][..],
        &["-sf", "t.zip", "a.txt", "b.txt", "d/c.txt"],
        &["-sf", "t.zip", "d"],
        &["-sf", "t.zip", "d/"],
        &["-sf", "-r", "t.zip", "d"],
        &["-sf", "-r", "t.zip", "d/"],
        &["-sf", "-r", "t.zip", "."],
        &["-sf", "-r", "t.zip", "./"],
        &["-sf", "-r", "-j", "t.zip", "./"],
        &["-sf", "-r", "t.zip", ".", "d"],
        &["-sf", "-r", "-D", "t.zip", "d"],
        &["-sf", "-r", "-D", "t.zip", "."],
        &["-sf", "-j", "t.zip", "d/c.txt", "a.txt"],
        &["-sf", "-j", "-r", "t.zip", "d"],
        &["-sf", "-k", "t.zip", "b.txt", "d/c.txt"],
        &["-sf", "-k", "-r", "t.zip", "d"],
        &["-sf", "t.zip", "./a.txt", "a.txt"],
        &["-sf", "t.zip", "a.txt", "a.txt", "b.txt"],
        &["-sf", "t.zip", "b.txt", "a.txt", "b.txt"],
        &["-sf", "t.zip", "d/../a.txt"],
        &["-sf", "t.zip", "../w/a.txt"],
        &["-sf", "-r", "t.zip", "d/.."],
        &["-sf", "t.zip", "."],
        &["-sf", "t.zip", "//tmp"],
        &["-sf", "t.zip", "//tmp/"],
        &["-sf", "t.zip", "/dev/null"],
        &["-sf", "t.zip", "nosuch", "a.txt"],
        &["-sf", "-MM", "t.zip", "a.txt", "nosuch"],
        &["-sf", "t.zip", "*.txt"],
        &["-sf", "-sd", "t.zip", "a.txt"],
        &["-sf", "-sd", "-r", "t.zip", "d"],
        &["-sf", "-q", "t.zip", "a.txt"],
        &["-sf", "-q", "-lf", "log", "t.zip", "a.txt"],
        &["-sf", "-lf", "log", "t.zip", "a.txt"],
        &["-sf", "-d", "t.zip", "a.txt"],
        &["-sf", "-f", "t.zip", "a.txt"],
        &["-sf", "-u", "t.zip", "a.txt"],
        &["-sf", "-O", "o.zip", "t.zip", "a.txt"],
        &["-sf", "-U", "t.zip", "a.txt"],
        &["-sf", "t.zip"],
        &["-sf", "-sf", "-sf-", "t.zip", "a.txt"],
        // nothing to do
        &["t.zip"],
        &["t.zip", "nosuch"],
        &["-r", "t.zip", "nosuch"],
        &["-r", "t.zip", "nosuch", "-x", "*.x"],
        &["-d", "t.zip", "a.txt"],
        &["-f", "t.zip", "a.txt"],
        &["-t", "01012002", "t.zip", "a.txt"],
        &["-MM", "t.zip", "nosuch"],
        &["t.zip", "/dev/null"],
        &["-R", "t.zip", "*.nomatch"],
        &["-MM", "-R", "t.zip", "*.nomatch"],
        &["-O", "o.zip", "t.zip", "a.txt"],
        &["-sf", "t.zip", "-x"],
    ] {
        add(args, std_tree(), None);
    }
    // -R, -i and -x: the wild card rules
    for args in [
        &["-sf", "-R", "t.zip", "*.txt"][..],
        &["-sf", "-R", "t.zip", "d/*"],
        &["-sf", "-R", "t.zip", "c.txt"],
        &["-sf", "-R", "t.zip", "*/*.txt"],
        &["-sf", "-R", "t.zip", "d/"],
        &["-sf", "-R", "t.zip", "*.txt", "-x", "b*"],
        &["-sf", "-R", "t.zip", "*", "-i", "*.txt"],
        &["-sf", "-R", "-D", "t.zip", "*"],
        &["-sf", "-r", "t.zip", ".", "-i", "*.txt"],
        &["-sf", "-r", "t.zip", ".", "-i", "d/*", "-x", "*c.txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "d/*", "b*"],
        &["-sf", "-r", "t.zip", ".", "-ws", "-x", "*.txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "d/?.txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "[a-b].txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "[!a-b].txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "[^a-b]*"],
        &["-sf", "-r", "t.zip", ".", "-nw", "-x", "*.txt"],
        &["-sf", "-r", "t.zip", ".", "-RE", "-x", "[a].txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "[a"],
        &["-sf", "-r", "t.zip", ".", "-x", "[]a]*"],
        &["-sf", "-r", "t.zip", ".", "-x", "[\\]a]*"],
        &["-sf", "-r", "t.zip", ".", "-x", "a\\"],
        &["-sf", "-r", "t.zip", ".", "-x", "[a-]*"],
        &["-sf", "-r", "t.zip", ".", "-x", "[-a]*"],
        &["-sf", "-r", "t.zip", ".", "-x", "[a-c-e]*"],
        &["-sf", "-r", "t.zip", ".", "-x", "*.t?t"],
        &["-sf", "-r", "t.zip", ".", "-x", "*x*t"],
        &["-sf", "-r", "t.zip", ".", "-x", "**"],
        &["-sf", "-r", "t.zip", ".", "-x", ""],
        &["-sf", "-r", "t.zip", ".", "-x", "./a.txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "/a.txt"],
        &["-sf", "-r", "t.zip", ".", "-x", "//tmp"],
        &["-sf", "-r", "-j", "t.zip", ".", "-x", "d/c.txt"],
        &["-sf", "-r", "-j", "t.zip", ".", "-x", "c.txt"],
        &["-sf", "-r", "-k", "t.zip", ".", "-x", "B.TXT"],
        &["-sf", "-r", "-k", "t.zip", ".", "-x", "b.txt"],
        &["-sf", "t.zip", "a.txt", "-x", "a.txt"],
        &["-sf", "t.zip", "a.txt", "-i", "b.txt"],
        &["-sf", "-r", "t.zip", "d", "-i", "d/"],
        &["-sf", "-r", "t.zip", "d", "-x", "d/"],
        &["-sf", "-r", "t.zip", ".", "-x", "@nosuch"],
        &["-sf", "-r", "t.zip", ".", "-x", "@"],
    ] {
        add(args, std_tree(), None);
    }
    // the date filters (the tree's times are 2001-09-09 01:46:40 UTC)
    for args in [
        &["-sf", "-t", "01012002", "t.zip", "a.txt"][..],
        &["-sf", "-t", "01012001", "t.zip", "a.txt"],
        &["-sf", "-t", "09092001", "t.zip", "a.txt"],
        &["-sf", "-tt", "09092001", "t.zip", "a.txt"],
        &["-sf", "-tt", "01012030", "t.zip", "a.txt"],
        &[
            "-sf",
            "-t",
            "2001-09-09",
            "-tt",
            "2001-09-10",
            "t.zip",
            "a.txt",
        ],
        &[
            "-sf", "-r", "-t", "01012001", "-tt", "01012002", "t.zip", ".",
        ],
    ] {
        add(args, std_tree(), None);
    }
    // links
    let link = || std_tree().symlink("l", "a.txt");
    let dangling = || std_tree().symlink("l", "nosuch");
    let dir_link = || std_tree().symlink("dl", "d");
    for (args, tree) in [
        (&["-sf", "t.zip", "l"][..], link()),
        (&["-sf", "-y", "t.zip", "l"][..], link()),
        (&["-sf", "t.zip", "l", "a.txt"][..], dangling()),
        (&["-sf", "-y", "t.zip", "l", "a.txt"][..], dangling()),
        (&["-sf", "-r", "t.zip", "dl"][..], dir_link()),
        (&["-sf", "-r", "-y", "t.zip", "dl"][..], dir_link()),
        (&["-sf", "-r", "t.zip", "."][..], dangling()),
        (&["-sf", "-r", "-y", "t.zip", "."][..], dangling()),
        (&["-sf", "-r", "-y", "t.zip", "."][..], dir_link()),
        // a link up the tree: followed until the kernel says ELOOP (or the
        // path is too long), a leaf under -y
        (
            &["-sf", "-r", "t.zip", "d"][..],
            std_tree().symlink("d/up", ".."),
        ),
        (
            &["-sf", "-r", "-y", "t.zip", "d"][..],
            std_tree().symlink("d/up", ".."),
        ),
        (
            &["-sf", "-r", "-j", "t.zip", "."][..],
            std_tree().symlink("d/self", "."),
        ),
        (&["t.zip", "l"][..], dangling()),
        (&["-MM", "t.zip", "l"][..], dangling()),
    ] {
        add(args, tree, None);
    }
    // special files, hidden files and unreadable ones (Review Focus 2: the
    // scan lists a mode-000 file and says nothing; the warning is the
    // reading's, Task 6)
    let fifo = || std_tree().fifo("f");
    let hidden = || std_tree().file(".hid", b"h").file("d/.h2", b"h");
    let unreadable = || std_tree().file_mode("b.txt", vec![b'x'; 2240], 0o000);
    for (args, tree) in [
        (&["-sf", "t.zip", "f", "a.txt"][..], fifo()),
        (&["-sf", "-FI", "t.zip", "f", "a.txt"][..], fifo()),
        (&["-sf", "-FI", "-q", "t.zip", "f", "a.txt"][..], fifo()),
        (&["-sf", "-r", "t.zip", "."][..], fifo()),
        (&["-sf", "-r", "t.zip", "."][..], hidden()),
        (&["-sf", "-R", "t.zip", "*"][..], hidden()),
        (&["-sf", "-r", "t.zip", ".", "-x", ".*"][..], hidden()),
        (
            &["-sf", "t.zip", "a.txt", "b.txt", "d/c.txt"][..],
            unreadable(),
        ),
        (&["-sf", "-r", "t.zip", "."][..], unreadable()),
        (&["-sf", "-MM", "t.zip", "b.txt"][..], unreadable()),
        (
            &["-sf", "-r", "t.zip", "d"][..],
            std_tree().dir_mode("d", 0o000),
        ),
        (
            &["-sf", "-r", "t.zip", "."][..],
            std_tree().dir_mode("d", 0o000),
        ),
    ] {
        add(args, tree, None);
    }
    // names from standard input, and standard input as a name
    for (args, stdin) in [
        (&["-sf", "-@", "t.zip"][..], &b"a.txt\nd/c.txt\n"[..]),
        (&["-sf", "-@", "t.zip", "b.txt"][..], &b"a.txt\n"[..]),
        (&["-sf", "-@", "t.zip"][..], &b"a.txt\nnosuch\n\nb.txt"[..]),
        (&["-sf", "-@", "-r", "t.zip"][..], &b"d\n"[..]),
        (&["-sf", "-@", "-R", "t.zip"][..], &b"*.txt\n"[..]),
        (&["-sf", "t.zip", "-"][..], &b"data"[..]),
        (&["-sf", "t.zip", "-", "a.txt"][..], &b"data"[..]),
        (&["-sf", "-x", "-", "t.zip", "-", "a.txt"][..], &b"data"[..]),
        (
            &["-sf", "-t", "01012030", "t.zip", "-", "a.txt"][..],
            &b"data"[..],
        ),
        (&["-sf"][..], &b"data"[..]),
        (&["-sf", "-@"][..], &b"a.txt\n"[..]),
    ] {
        add(args, std_tree(), Some(stdin));
    }
    // pattern files
    let lists = || {
        std_tree()
            .file("list", b"*.txt\n")
            .file("names", b"a.txt\nd/c.txt\n")
    };
    for args in [
        &["-sf", "-r", "t.zip", ".", "-x", "@list"][..],
        &["-sf", "-r", "t.zip", ".", "-i", "@list"],
        &["-sf", "t.zip", "-i", "@names"],
    ] {
        add(args, lists(), None);
    }
    // names that are not plain
    let odd = || {
        std_tree()
            .file_at(b"new\nline", b"x", 0o644)
            .file_at(b"-n", b"x", 0o644)
            .file_at(b"tab\there", b"x", 0o644)
            .file_at(b"*", b"x", 0o644)
            .file_at(b"sp ace", b"x", 0o644)
    };
    for args in [
        &["-sf", "t.zip", "new\nline"][..],
        &["-sf", "-r", "t.zip", "."],
        &["-sf", "t.zip", "--", "-n"],
        &["-sf", "t.zip", "./-n"],
        &["-sf", "-r", "t.zip", ".", "-x", "\\*"],
        &["-sf", "-r", "t.zip", ".", "-nw", "-x", "\\*"],
        &["-sf", "-r", "t.zip", ".", "-nw", "-x", "*"],
        &["-sf", "-k", "t.zip", "sp ace", "tab\there"],
        &["-sf", "-r", "-j", "t.zip", "d", "."],
    ] {
        add(args, odd(), None);
    }
    // names the archive would store twice
    let twins = || {
        std_tree()
            .dir("e")
            .file("d/a.txt", b"x")
            .file("e/a.txt", b"y")
    };
    for args in [
        &["-sf", "-j", "t.zip", "a.txt", "d/a.txt"][..],
        &["-sf", "-j", "t.zip", "e/a.txt", "d/a.txt", "a.txt"],
        &[
            "-sf", "-j", "t.zip", "d/a.txt", "e/a.txt", "d/a.txt", "a.txt", "e/a.txt",
        ],
        &["-sf", "-j", "-r", "t.zip", "."],
        &["-sf", "t.zip", "a.txt", "d/a.txt", "e/a.txt"],
        &["t.zip", "-j", "a.txt", "d/a.txt"],
    ] {
        add(args, twins(), None);
    }
    out
}

/// The tree the byte matrix writes from: the standard tree and a text file
/// long enough to slide deflate's window many times (`big.txt`, 300000
/// bytes), a random one that does not deflate (`r.bin`, 70000 bytes,
/// several blocks), a small random one that deflate makes larger
/// (`s.bin`, 600 bytes: stored instead), an empty file, CR LF lines, a
/// name with the `.Z` suffix (`-n`'s default list), a link to `a.txt` and
/// a dangling one.
pub fn zip_bytes_tree() -> ZipTree {
    let mut crlf = Vec::new();
    for i in 0..300 {
        crlf.extend_from_slice(format!("crlf line {i}\r\n").as_bytes());
    }
    crlf.extend_from_slice(b"lone cr\rend\r");
    ZipTree::standard()
        .file("big.txt", text(300_000, 11))
        .file("r.bin", random(70_000, 12))
        .file("s.bin", random(600, 13))
        .file("e.txt", b"")
        .file("crlf.txt", crlf)
        .file("x.Z", text(5_000, 14))
        .file_mode("ro.txt", b"read only\n", 0o444)
        .symlink("l", "a.txt")
        .symlink("dl", "nosuch")
}

/// Task 6's byte matrix: new archives written from [`zip_bytes_tree`] (or
/// the standard tree) under each option that changes what is written or
/// said, compared byte for byte with the reference: the archive (or the
/// archive on standard output), both streams, the exit code and the tree.
/// A 300-byte line and a short one: `fgets(e, MAXCOM + 1)` cuts the first.
const LONG_LINE: &[u8] = b"0123456789012345678901234567890123456789012345678901234567890123456789\
012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\
012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\
01234567890123456789012345678901234567890123456789\nshort\n";

pub fn zip_bytes_matrix(flavour: &'static str) -> Vec<Case<'static>> {
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str], tree: ZipTree, stdin: Option<&[u8]>| {
        let mut c = zip_case("zip", args, tree);
        c.zip_flavour = Some(flavour);
        c.stdin = stdin.map(<[u8]>::to_vec);
        out.push(c);
    };
    const ALL: [&str; 10] = [
        "a.txt", "b.txt", "d", "d/c.txt", "big.txt", "r.bin", "s.bin", "e.txt", "x.Z", "ro.txt",
    ];
    let all = |pre: &[&'static str]| -> Vec<&'static str> {
        let mut v = pre.to_vec();
        v.push("t.zip");
        v.extend_from_slice(&ALL);
        v
    };
    // levels and methods
    for pre in [
        &["-0"][..],
        &["-1"],
        &["-2"],
        &["-3"],
        &["-4"],
        &["-5"],
        &["-6"],
        &["-7"],
        &["-8"],
        &["-9"],
        &[],
        &["-Z", "store"],
        &["-Z", "deflate"],
        &["-0", "-Z", "deflate"],
        &["-Z", "deflate", "-0"],
        &["-Z", "store", "-9"],
        // attributes, links, paths, line ends, suffixes
        &["-X"],
        &["-X-"],
        &["-y"],
        &["-D"],
        &["-j"],
        &["-k"],
        &["-l"],
        &["-ll"],
        &["-n", ".txt"],
        &["-n", ".txt:.bin"],
        &["-n", ":"],
        &["-9", "-n", ".txt"],
        // Zip64 and descriptors
        &["-fz"],
        &["-fz-"],
        &["-fd"],
        &["-fd", "-0"],
        // messages
        &["-q"],
        &["-v"],
        &["-dc"],
        &["-db"],
        &["-du"],
        &["-dv"],
        &["-dc", "-db", "-du", "-dv"],
        &["-dd"],
        &["-dd", "-ds", "32k"],
        &["-dg"],
        &["-dg", "-ds", "32k"],
        &["-dd", "-ds", "32k", "-v"],
        &["-v", "-ds", "32k", "-0"],
        &["-dd", "-ds", "32k", "-q"],
        &["-dg", "-ds", "32k", "-q"],
    ] {
        add(&all(pre), zip_bytes_tree(), None);
    }
    // the same entry kinds one at a time
    for args in [
        &["t.zip", "l"][..],
        &["-y", "t.zip", "l"],
        &["-y", "t.zip", "dl"],
        &["-y", "-0", "t.zip", "l"],
        &["t.zip", "e.txt"],
        &["t.zip", "d"],
        &["-r", "t.zip", "d"],
        &["-r", "-D", "t.zip", "d"],
        &["t.zip", "s.bin"],
        &["-l", "t.zip", "crlf.txt", "r.bin", "a.txt"],
        &["-ll", "t.zip", "crlf.txt", "r.bin", "a.txt"],
        &["-l", "-0", "t.zip", "crlf.txt", "r.bin", "a.txt"],
        &["-ll", "-0", "t.zip", "crlf.txt", "r.bin", "a.txt"],
        &["-ll", "-v", "t.zip", "crlf.txt", "big.txt"],
        &["-fz", "-0", "t.zip", "a.txt", "d"],
        &["-v", "t.zip", "e.txt", "d"],
        &["-r", "t.zip", "."],
        &["-r", "-q", "t.zip", ".", "-x", "*.bin"],
    ] {
        add(args, zip_bytes_tree(), None);
    }
    // standard output (a pipe: data descriptors, no going back)
    for args in [
        &["-", "a.txt", "b.txt", "d"][..],
        &["-", "a.txt", "b.txt", "big.txt", "r.bin", "s.bin", "e.txt"],
        &["-0", "-", "a.txt", "b.txt"],
        &["-q", "-", "big.txt"],
        &["-v", "-", "a.txt", "b.txt"],
        &["-fz", "-", "a.txt"],
        &["-y", "-", "l"],
        &["-l", "-", "crlf.txt"],
        &["-1", "-", "big.txt"],
        &["-9", "-", "big.txt"],
    ] {
        add(args, zip_bytes_tree(), None);
    }
    // standard input as an entry, to a file and to a pipe
    let hello = &b"hello\n"[..];
    let long = text(100_000, 21);
    let long: &'static [u8] = Box::leak(long.into_boxed_slice());
    for (args, stdin) in [
        (&["t.zip", "-"][..], hello),
        (&["t.zip", "-", "a.txt"], hello),
        (&["-v", "t.zip", "-"], long),
        (&["-0", "t.zip", "-"], hello),
        (&["-fz", "t.zip", "-"], hello),
        (&["-fz-", "t.zip", "-"], hello),
        (&[], hello),
        (&[], long),
        (&[], b""),
        (&["-0"], hello),
        (&["-", "-"], hello),
        (&["-q", "-", "-"], long),
        (&["-l", "t.zip", "-"], b"a\nb\n"),
        (&["-db", "-dc", "-du", "t.zip", "-", "a.txt"], hello),
    ] {
        add(args, zip_bytes_tree(), Some(stdin));
    }
    // comments from standard input
    for (args, stdin) in [
        (&["-z", "t.zip", "a.txt"][..], &b"hi\n"[..]),
        (&["-z", "t.zip", "a.txt"], b"one\ntwo\n.\nthree\n"),
        (&["-z", "t.zip", "a.txt"], b""),
        (&["-z", "-q", "t.zip", "a.txt"], b"quiet\n"),
        (&["-c", "t.zip", "a.txt", "b.txt"], b"first\nsecond\n"),
        (&["-c", "t.zip", "a.txt", "b.txt"], b"only one\n"),
        (&["-c", "-z", "t.zip", "a.txt"], b"entry\nzip\n.\n"),
        // after -@ the questions read standard error (a pipe here: nothing)
        (&["-c", "-@", "t.zip"], b"a.txt\nb.txt\n"),
        (&["-z", "-@", "t.zip"], b"a.txt\n"),
        // a NUL ends a line for the C's strlen
        (&["-c", "t.zip", "a.txt", "b.txt"], b"ab\0cd\nsecond\n"),
        (&["-z", "t.zip", "a.txt"], b"one\0two\nthree\n.\n"),
        // a line longer than MAXCOM is two answers
        (&["-c", "t.zip", "a.txt", "b.txt"], LONG_LINE),
        (&["-z", "t.zip", "a.txt"], LONG_LINE),
    ] {
        add(args, zip_bytes_tree(), Some(stdin));
    }
    // nothing to write
    add(&["-r", "t.zip", "."], ZipTree::new(), None);
    add(&["t.zip"], ZipTree::new(), None);
    // unreadable inputs among readable ones (Review Focus 2)
    let unreadable = || ZipTree::standard().file_mode("b.txt", vec![b'x'; 2240], 0o000);
    for args in [
        &["t.zip", "a.txt", "b.txt", "d/c.txt"][..],
        &["-r", "t.zip", "."],
        &["-q", "t.zip", "a.txt", "b.txt"],
        &["-MM", "t.zip", "a.txt", "b.txt", "d/c.txt"],
        &["t.zip", "b.txt"],
        &["-", "a.txt", "b.txt"],
        &["-dc", "-db", "t.zip", "a.txt", "b.txt", "d/c.txt"],
    ] {
        add(args, unreadable(), None);
    }
    // -m, -o and -sd over the standard tree
    for args in [
        &["-m", "t.zip", "a.txt", "d/c.txt"][..],
        &["-mr", "t.zip", "d"],
        &["-m", "-D", "-r", "t.zip", "d"],
        &["-v", "-m", "t.zip", "a.txt", "d", "d/c.txt"],
        &["-o", "t.zip", "a.txt", "b.txt"],
        &["-o", "t.zip", "d"],
        &["-o", "-X", "t.zip", "a.txt"],
        &["-sd", "t.zip", "a.txt", "b.txt"],
        &["-sd", "-", "a.txt"],
        &["-db", "-dc", "-r", "t.zip", "."],
    ] {
        add(
            args,
            ZipTree::standard().times("b.txt", 1_100_000_000, 1_100_000_000),
            None,
        );
    }
    // where the archive cannot be made
    for (args, tree) in [
        (&["nodir/t.zip", "a.txt"][..], ZipTree::standard()),
        (
            &["ro/t.zip", "a.txt"],
            ZipTree::standard().dir_mode("ro", 0o555),
        ),
        (&["-b", "nodir", "t.zip", "a.txt"], ZipTree::standard()),
        (&["-b", "d", "t.zip", "a.txt"], ZipTree::standard()),
        (&["d/t.zip", "a.txt", "b.txt"], ZipTree::standard()),
    ] {
        add(args, tree, None);
    }
    out
}

// ---- Updating archives (0.19.0 Task 7) ----

/// The archive `zip args` writes over `tree`, made by stuffr in `flavour`
/// (byte-identical to the reference for new archives: Task 6's matrix), in
/// a scratch directory; `out` names the archive (`-` for standard output,
/// returned as written there). An input for the update cases, the same on
/// both sides.
pub fn zip_made(flavour: &str, tree: &ZipTree, args: &[&str], out: &str) -> Vec<u8> {
    zip_made_with(flavour, tree, args, out, b"")
}

/// [`zip_made`] with `stdin` piped in (`-z`'s comment).
pub fn zip_made_with(
    flavour: &str,
    tree: &ZipTree,
    args: &[&str],
    out: &str,
    stdin: &[u8],
) -> Vec<u8> {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt;
    let s = ScratchDir::unique("zip-made");
    std::fs::create_dir_all(&*s).unwrap();
    tree.materialise(&s);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stuffr"));
    cmd.arg0("zip")
        .args(args)
        .current_dir(&*s)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("STUFFR_ZIP_FLAVOR", flavour)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(&mut cmd).unwrap();
    let mut pipe = child.stdin.take().unwrap();
    let _ = pipe.write_all(stdin);
    drop(pipe);
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "zip {args:?}: {o:?}");
    if out == "-" {
        o.stdout
    } else {
        std::fs::read(s.join(out)).unwrap()
    }
}

/// `stuffr pack -o t.zip names` over `tree`: an archive another zip writer
/// made.
pub fn packed_zip(tree: &ZipTree, names: &[&str]) -> Vec<u8> {
    let s = ScratchDir::unique("zip-pack");
    std::fs::create_dir_all(&*s).unwrap();
    tree.materialise(&s);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stuffr"));
    cmd.arg("pack")
        .arg("-o")
        .arg("t.zip")
        .args(names)
        .current_dir(&*s)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let o = output(&mut cmd).unwrap();
    assert!(o.status.success(), "stuffr pack {names:?}: {o:?}");
    std::fs::read(s.join("t.zip")).unwrap()
}

/// A fake `unzip` in `fb/` (a shell script): `unzip -v` prints `version`
/// (nothing when empty), any other call prints its arguments and exits
/// `code`. With `PATH=fb:/usr/bin:/bin` both sides run it for `-T`.
pub fn with_fake_unzip(tree: ZipTree, version: &str, code: i32) -> ZipTree {
    let v = if version.is_empty() {
        String::new()
    } else {
        format!("echo '{version}'; echo more; ")
    };
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = -v ]; then {v}exit 0; fi\necho unzip-args: \"$@\"\nexit {code}\n"
    );
    tree.file_mode("fb/unzip", script, 0o755)
}

/// A `-TT` program `fb/probe` that prints its arguments and its
/// environment (less stuffr's `STUFFR_` variables, which only stuffr's side
/// has), with `PATH=fb:...` ([`FAKE_UNZIP_PATH`]).
pub fn env_probe(tree: ZipTree) -> ZipTree {
    tree.file_mode(
        "fb/probe",
        "#!/bin/sh\necho args: \"$@\"\nenv | grep -v '^STUFFR_' | sort\nexit 0\n",
        0o755,
    )
}

/// The PATH that finds [`with_fake_unzip`]'s script first.
pub const FAKE_UNZIP_PATH: (&str, &str) = ("PATH", "fb:/usr/bin:/bin");

/// `b` with `n` bytes from `at` replaced by `with`.
fn patched(mut b: Vec<u8>, at: usize, with: &[u8]) -> Vec<u8> {
    b[at..at + with.len()].copy_from_slice(with);
    b
}

/// Task 7's byte matrix: archives already at the path, updated, freshened,
/// deleted from, copied, grown, tested, commented, adjusted, damaged, in
/// `flavour`, compared byte for byte with the reference (both streams, the
/// exit code, every archive and the rest of the tree). `failing_tests`:
/// whether to include the `-T` runs whose test fails (Ubuntu's reference
/// double-frees there: ruling Z3, pinned stuffr-only).
pub fn zip_update_matrix(flavour: &'static str, failing_tests: bool) -> Vec<Case<'static>> {
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str],
                   tree: ZipTree,
                   stdin: Option<&[u8]>,
                   env: &[(&'static str, &'static str)]| {
        let mut c = zip_case("zip", args, tree);
        c.zip_flavour = Some(flavour);
        c.stdin = stdin.map(<[u8]>::to_vec);
        c.env = env.to_vec();
        out.push(c);
    };
    let std = ZipTree::standard;
    let ab = zip_made(flavour, &std(), &["t.zip", "a.txt", "b.txt"], "t.zip");
    let all = zip_made(flavour, &std(), &["-r", "t.zip", "."], "t.zip");
    let with_x = zip_made(
        flavour,
        &std().file("x.txt", b"x\n"),
        &["t.zip", "a.txt", "b.txt", "x.txt"],
        "t.zip",
    );
    let commented = zip_made_with(
        flavour,
        &std(),
        &["-z", "t.zip", "a.txt"],
        "t.zip",
        b"a long comment line here\nand a second one\n.\n",
    );
    let commented_entries = zip_made_with(
        flavour,
        &std(),
        &["-c", "t.zip", "a.txt", "b.txt"],
        "t.zip",
        b"a long entry comment for a\nanother for b\n",
    );
    let streamed = zip_made(flavour, &std(), &["-", "a.txt", "b.txt"], "-");
    let fz = zip_made(
        flavour,
        &std(),
        &["-fz", "t.zip", "a.txt", "b.txt"],
        "t.zip",
    );
    let fd = zip_made(
        flavour,
        &std(),
        &["-fd", "t.zip", "a.txt", "b.txt"],
        "t.zip",
    );
    let x_only = zip_made(flavour, &std(), &["-X", "t.zip", "a.txt", "b.txt"], "t.zip");
    let packed = packed_zip(&std(), &["a.txt", "b.txt"]);
    let mut prefixed = b"PREFIX-OF-AN-SFX\n".to_vec();
    prefixed.extend_from_slice(&ab);
    let a = || std().file("t.zip", ab.clone());
    // b.txt newer than its entry
    let newer = || a().times("b.txt", 1_100_000_000, INPUT_ATIME);

    // add, update, freshen, delete
    for (args, tree) in [
        (&["t.zip", "a.txt"][..], a()),
        (&["t.zip", "a.txt", "d/c.txt"], a()),
        (&["t.zip", "d/c.txt"], a()),
        (&["-0", "t.zip", "b.txt"], a()),
        (&["-9", "t.zip", "b.txt", "d"], a()),
        (&["-u", "t.zip", "a.txt", "b.txt", "d/c.txt"], a()),
        (&["-u", "t.zip", "a.txt", "b.txt"], a()),
        (&["-u", "t.zip", "a.txt", "b.txt"], newer()),
        (&["-u", "t.zip"], newer()),
        (&["-u", "-v", "t.zip"], newer()),
        (&["-f", "t.zip"], a()),
        (&["-f", "t.zip"], newer()),
        (&["-f", "t.zip", "b.txt", "d/c.txt"], newer()),
        (&["-d", "t.zip", "a.txt"], a()),
        (&["-d", "t.zip", "a*"], a()),
        (&["-d", "t.zip", "*"], a()),
        (&["-d", "t.zip", "nosuch"], a()),
        (&["-d", "t.zip", "a.txt", "b.txt"], a()),
        (&["-d", "-du", "-dc", "-db", "t.zip", "b.txt"], a()),
        (&["-d", "t.zip", "d/*"], std().file("t.zip", all.clone())),
        (
            &["-d", "-v", "t.zip", "d/*"],
            std().file("t.zip", all.clone()),
        ),
        (&["t.zip", "*"], a()),
        (&["t.zip", "*.txt"], a()),
        (&["-x", "b.txt", "-u", "t.zip"], newer()),
        (&["-i", "b*", "-f", "t.zip"], newer()),
        (&["-g", "t.zip", "d/c.txt"], a()),
        (&["-g", "t.zip", "a.txt"], a()),
        (&["-o", "t.zip", "d/c.txt"], newer()),
        (&["-o", "t.zip"], a()),
        (&["-m", "t.zip", "a.txt", "d/c.txt"], a()),
        (&["-mu", "t.zip", "a.txt", "b.txt"], newer()),
        (&["-m", "-v", "-r", "t.zip", "d"], a()),
        (
            &["-FS", "t.zip", "a.txt", "b.txt"],
            std().file("t.zip", with_x.clone()),
        ),
        (
            &["-FS", "-v", "t.zip", "a.txt", "b.txt"],
            std().file("t.zip", with_x.clone()),
        ),
        (&["-FS", "t.zip", "a.txt", "b.txt"], a()),
        (
            &["-FS", "-r", "t.zip", "."],
            std().file("t.zip", all.clone()),
        ),
        (
            &["-FS", "-dc", "t.zip", "a.txt", "d/c.txt"],
            std().file("t.zip", with_x.clone()),
        ),
        (
            &["-DF", "t.zip", "a.txt", "b.txt", "--out", "o.zip"],
            newer(),
        ),
        (&["-t", "06012010", "t.zip", "a.txt", "b.txt"], newer()),
        (&["-tt", "06012010", "-d", "t.zip", "a.txt", "b.txt"], a()),
        (&["-X-", "t.zip", "a.txt"], a()),
        (&["-X", "t.zip", "a.txt"], a()),
        (
            &["-X-", "t.zip", "a.txt"],
            std().file("t.zip", x_only.clone()),
        ),
        (&["-v", "t.zip", "d/c.txt"], a()),
        (&["-v", "t.zip", "d/c.txt"], std().file("t.zip", fz.clone())),
        (
            &["-dc", "-db", "-du", "-dv", "t.zip", "a.txt", "d/c.txt"],
            a(),
        ),
        (&["-dd", "-ds", "32k", "t.zip", "a.txt"], a()),
        (&["-dg", "-ds", "32k", "t.zip", "a.txt"], a()),
        (&["-sd", "-u", "t.zip"], newer()),
        (&["-sd", "t.zip", "d/c.txt"], a()),
        (&["-q", "t.zip", "a.txt", "d/c.txt"], a()),
        (&["-sf", "t.zip"], a()),
        (&["-sf", "t.zip", "d/c.txt"], a()),
        (&["-sf", "-d", "t.zip", "a.txt"], a()),
        (&["-sf", "-u", "t.zip"], newer()),
        // copy mode and --out
        (&["-U", "t.zip", "a.txt", "--out", "o.zip"], a()),
        (&["-U", "t.zip", "nosuch", "--out", "o.zip"], a()),
        (&["-U", "t.zip", "-", "--out", "o.zip"], a()),
        (&["-U", "-v", "t.zip", "*", "--out", "o.zip"], a()),
        (&["t.zip", "d/c.txt", "--out", "o.zip"], a()),
        (&["t.zip", "--out", "o.zip"], a()),
        (&["-d", "t.zip", "a.txt", "--out", "o.zip"], a()),
        // Review Focus 3: the archive among its own inputs
        (&["t.zip", "a.txt", "b.txt", "d", "t.zip"], a()),
        (&["-r", "t.zip", "."], a()),
        (&["-r", "-v", "t.zip", "."], a()),
        (&["-r", "t.zip", "."], std().file("t.zip", all.clone())),
        // Review Focus 4: the temporary cannot be made
        (&["-b", "ro", "t.zip", "d/c.txt"], a().dir_mode("ro", 0o555)),
        (&["-b", "nodir", "t.zip", "d/c.txt"], a()),
        // archives other writers made, or other options did
        (&["t.zip", "d/c.txt"], std().file("t.zip", streamed.clone())),
        (&["t.zip", "a.txt"], std().file("t.zip", streamed.clone())),
        (&["t.zip", "d/c.txt"], std().file("t.zip", fz.clone())),
        (&["t.zip", "a.txt"], std().file("t.zip", fz.clone())),
        (&["t.zip", "d/c.txt"], std().file("t.zip", fd.clone())),
        (&["t.zip", "d/c.txt"], std().file("t.zip", x_only.clone())),
        (&["t.zip", "d/c.txt"], std().file("t.zip", packed.clone())),
        (&["t.zip", "a.txt"], std().file("t.zip", packed.clone())),
        (
            &["-d", "t.zip", "a.txt"],
            std().file("t.zip", packed.clone()),
        ),
        (
            &["t.zip", "d/c.txt"],
            std().file("t.zip", commented.clone()),
        ),
        // a prefix (self-extractor)
        (&["p.zip", "d/c.txt"], std().file("p.zip", prefixed.clone())),
        (&["-A", "p.zip"], std().file("p.zip", prefixed.clone())),
        (&["-J", "p.zip"], std().file("p.zip", prefixed.clone())),
        (&["-A", "t.zip"], a()),
        (&["-J", "t.zip"], a()),
        // archives that cannot be updated
        (
            &["t.zip", "a.txt"],
            a().file_mode("t.zip", ab.clone(), 0o444),
        ),
        (&["t.zip", "a.txt"], std().file("t.zip", &ab[..100])),
        (
            &["t.zip", "a.txt"],
            std().file("t.zip", &ab[..ab.len() - 30]),
        ),
        (&["t.zip", "a.txt"], std().file("t.zip", b"")),
        (&["t.zip", "a.txt"], std().dir("t.zip")),
        (&["-s-", "t.zip", "a.txt"], a()),
    ] {
        add(args, tree, None, &[]);
    }
    // damaged archives: the end record, the central directory, local headers
    let eocd = ab.len() - 22;
    let cd = ab.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    let second_local = ab[4..].windows(4).position(|w| w == b"PK\x03\x04").unwrap() + 4;
    for bytes in [
        // more entries than the directory holds, fewer
        patched(ab.clone(), eocd + 10, &[3, 0]),
        patched(ab.clone(), eocd + 10, &[1, 0]),
        // a comment longer than the file
        patched(ab.clone(), eocd + 20, &[40, 0]),
        // the directory's offset past the end, before its start
        patched(ab.clone(), eocd + 16, &[0xff, 0xff, 0, 0]),
        patched(ab.clone(), eocd + 16, &[1, 0, 0, 0]),
        // a damaged central signature
        patched(ab.clone(), cd + 2, b"\x09\x09"),
        // a central name of length 0
        patched(ab.clone(), cd + 28, &[0, 0]),
        // a local header that is not one, a local name that differs
        patched(ab.clone(), second_local, b"XX"),
        patched(ab.clone(), second_local + 30, b"B"),
        patched(ab.clone(), 30, b"A"),
        // local version, flags and CRC that differ from the central ones
        patched(ab.clone(), 4, &[20]),
        patched(ab.clone(), 6, &[8]),
        patched(ab.clone(), 14, &[0]),
        // a disk number on the end record
        patched(ab.clone(), eocd + 4, &[1, 0]),
    ] {
        for args in [
            &["t.zip", "d/c.txt"][..],
            &["-u", "t.zip", "a.txt"],
            &["-v", "t.zip", "a.txt"],
        ] {
            add(args, std().file("t.zip", bytes.clone()), None, &[]);
        }
    }
    // comments
    for (args, tree, stdin) in [
        (
            &["-c", "t.zip", "d/c.txt"][..],
            a(),
            &b"one\ntwo\nthree\n"[..],
        ),
        (&["-c", "t.zip"], a(), b"one\ntwo\n"),
        (&["-c", "-u", "t.zip"], newer(), b"one\ntwo\n"),
        (&["-z", "t.zip"], a(), b"new\n.\n"),
        (
            &["-z", "t.zip"],
            std().file("t.zip", commented.clone()),
            b"new\n.\n",
        ),
        (
            &["-z", "t.zip", "d/c.txt"],
            std().file("t.zip", commented.clone()),
            b"x\ny\n.\n",
        ),
        (
            &["-z", "-q", "t.zip"],
            std().file("t.zip", commented.clone()),
            b"q\n.\n",
        ),
        // -g writes in place: a shorter comment leaves the old tail
        (
            &["-g", "-z", "t.zip"],
            std().file("t.zip", commented.clone()),
            b"x\n.\n",
        ),
        (
            &["-g", "-z", "t.zip", "d/c.txt"],
            std().file("t.zip", commented.clone()),
            b"x\n.\n",
        ),
        (
            &["-g", "-c", "t.zip", "d/c.txt"],
            std().file("t.zip", commented_entries.clone()),
            b"c\n",
        ),
        (
            &["-c", "t.zip", "d/c.txt"],
            std().file("t.zip", commented_entries.clone()),
            b"c\n",
        ),
        (
            &["-z", "t.zip"],
            std().file("t.zip", commented.clone()),
            b"",
        ),
    ] {
        add(args, tree, Some(stdin), &[]);
    }
    // -T and -TT
    let fake = |v: &str, code: i32| with_fake_unzip(a(), v, code);
    for (args, tree) in [
        (&["-T", "t.zip", "d/c.txt"][..], a()),
        (&["-T", "t.zip"], a()),
        (&["-T", "-v", "t.zip", "d/c.txt"], a()),
        (&["-T", "-m", "t.zip", "d/c.txt"], a()),
        (&["-T", "t.zip", "d/c.txt"], fake("", 0)),
        (
            &["-T", "t.zip", "d/c.txt"],
            fake("UnZip 6.00 of 20 April 2009", 0),
        ),
        (
            &["-T", "t.zip", "d/c.txt"],
            fake("UnZip 5.52 of 28 February 2005", 0),
        ),
        (
            &["-T", "-fz", "t.zip", "d/c.txt"],
            fake("UnZip 6.00 of 20 April 2009", 0),
        ),
        (&["-T", "-v", "t.zip", "d/c.txt"], fake("not unzip", 0)),
        (&["-T", "-TT", "fb/unzip", "t.zip", "d/c.txt"], fake("", 0)),
        (&["-T", "-TT", "true", "t.zip", "d/c.txt"], a()),
        (&["-TT", "false", "t.zip", "d/c.txt"], a()),
        (&["-T", "-TT", "true {}", "t.zip", "d/c.txt"], a()),
        (&["-T", "-b", "d", "t.zip", "a.txt"], fake("", 0)),
        // Apple spawns with an empty environment, Ubuntu's system() keeps it
        (&["-T", "-TT", "probe", "t.zip", "a.txt"], env_probe(a())),
    ] {
        add(args, tree, None, &[FAKE_UNZIP_PATH]);
    }
    if failing_tests {
        for (args, tree) in [
            (&["-T", "t.zip", "d/c.txt"][..], fake("", 1)),
            (&["-T", "-TT", "false", "t.zip", "d/c.txt"], a()),
            (
                &["-T", "-fz", "t.zip", "d/c.txt"],
                fake("UnZip 5.52 of 28 February 2005", 0),
            ),
            (&["-T", "-m", "t.zip", "d/c.txt"], fake("", 2)),
        ] {
            add(args, tree, None, &[FAKE_UNZIP_PATH]);
        }
    }
    // an unreadable or vanished file whose entry is updated
    for args in [
        &["t.zip", "a.txt", "d/c.txt"][..],
        &["-MM", "t.zip", "a.txt", "d/c.txt"],
        &["-u", "t.zip"],
    ] {
        add(
            args,
            newer().file_mode("a.txt", b"hello\n", 0o000),
            None,
            &[],
        );
    }
    // a directory entry whose name is a file now
    let dir_zip = zip_made(flavour, &std(), &["-r", "t.zip", "d"], "t.zip");
    add(
        &["t.zip", "d/"],
        ZipTree::new()
            .file("d", b"now a file\n")
            .file("t.zip", dir_zip),
        None,
        &[],
    );
    out
}

/// Review Focus 4 and the record's signal table (0.19.0 Task 7), against
/// this platform's reference in `flavour`: `zip t.zip big` over a new
/// archive and over an existing one, interrupted once the temporary
/// `ziXXXXXX` holds data. INT, TERM, ABRT, BUS, ILL and SEGV: exit 9,
/// `  adding: big\n\n\nzip error: Interrupted (aborting)\n` on standard
/// output, nothing on standard error, the temporary removed and the old
/// archive byte for byte as it was (also with INT ignored at start: zip's
/// `signal()` overrides it). HUP and QUIT: killed by the signal, the
/// temporary left, the old archive untouched. Both sides must agree.
pub fn zip_interrupts_match(flavour: &'static str) {
    use super::interrupt::*;
    use std::os::unix::process::ExitStatusExt;
    /// Exit code, signal, standard output, standard error, what is left.
    type Seen = (Option<i32>, Option<i32>, Vec<u8>, Vec<u8>, Vec<String>);
    let _serial = interrupt_lock();
    let Some(dir) = zip_dir() else {
        return;
    };
    let reference = Path::new(dir).join("zip");
    if !require_reference(&reference) {
        return;
    }
    let stuffr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_stuffr"));
    let env = [("STUFFR_ZIP_FLAVOR", flavour), ("LANG", "C"), ("TZ", "UTC")];
    // an archive with an entry (an empty one is removed at zip's
    // writability check, before the temporary is made)
    let old = stored_zip(b"a.txt", b"hello\n");
    let caught = [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGILL,
        libc::SIGSEGV,
    ];
    // (signal, an archive at the path, SIGINT inherited, -g)
    let mut rows: Vec<(i32, bool, Inherit, bool)> = Vec::new();
    for &sig in &caught {
        rows.push((sig, true, Inherit::Default, false));
    }
    rows.push((libc::SIGINT, false, Inherit::Default, false));
    rows.push((libc::SIGINT, true, Inherit::IgnoreInt, false));
    rows.push((libc::SIGHUP, true, Inherit::Default, false));
    rows.push((libc::SIGQUIT, false, Inherit::Default, false));
    rows.push((libc::SIGINT, true, Inherit::Default, true));
    rows.push((libc::SIGTERM, true, Inherit::Default, true));
    for (sig, existing, inherit, grow) in rows {
        let args: &[&str] = if grow {
            &["-g", "t.zip", "big"]
        } else {
            &["t.zip", "big"]
        };
        let mut seen: Vec<Seen> = Vec::new();
        let mut reference_hung = false;
        for exe in [&reference, &stuffr] {
            let s = ScratchDir::unique("zip-intr");
            let prepare = |mib: usize| {
                std::fs::write(s.join("big"), big_input(mib)).unwrap();
                if existing {
                    std::fs::write(s.join("t.zip"), &old).unwrap();
                }
            };
            // zip grows the archive itself under -g, stuffr a temporary
            let grown = old.len() as u64 + 100_000;
            let dir: &Path = &s;
            let ready = |n: &str| {
                let len = std::fs::metadata(dir.join(n)).map_or(0, |m| m.len());
                (is_temp_name(n.as_bytes()) && len > 0) || (grow && n == "t.zip" && len > grown)
            };
            let Some(r) =
                interrupt_prepared(exe, "zip", args, &s, &env, &prepare, inherit, sig, &ready)
            else {
                // a hung stuffr panics inside: only the reference gets here
                reference_hung = true;
                continue;
            };
            let why = format!("{exe:?} signal {sig} existing {existing} -g {grow}");
            // zip's -g rewrites the archive in place (deviation 13)
            if existing && !(grow && exe == &reference) {
                assert_eq!(std::fs::read(s.join("t.zip")).unwrap(), old, "{why}");
            }
            let left: Vec<String> = r
                .left
                .iter()
                .map(|n| {
                    if is_temp_name(n.as_bytes()) {
                        "zi??????".to_owned()
                    } else {
                        n.clone()
                    }
                })
                .collect();
            seen.push((r.status.code(), r.status.signal(), r.stdout, r.stderr, left));
        }
        assert!(
            seen.len() == 2 || (seen.len() == 1 && reference_hung),
            "signal {sig}: stuffr's side did not run"
        );
        if seen.len() != 2 {
            continue;
        }
        assert_eq!(
            seen[0], seen[1],
            "signal {sig}, existing archive {existing}, -g {grow}"
        );
        let (code, signal, stdout, stderr, left) = &seen[1];
        if caught.contains(&sig) {
            assert_eq!(*code, Some(9), "signal {sig}");
            let restore = if grow {
                "attempting to restore t.zip to its previous state\n"
            } else {
                ""
            };
            assert_eq!(
                String::from_utf8_lossy(stdout),
                format!("  adding: big\n\n\nzip error: Interrupted (aborting)\n{restore}")
            );
            assert!(stderr.is_empty());
            assert!(!left.iter().any(|n| n == "zi??????"), "{left:?}");
        } else {
            assert_eq!(*signal, Some(sig));
            assert!(left.iter().any(|n| n == "zi??????"), "{left:?}");
        }
    }
}

// ---- Task 8: -F, -FF and split archives ----

/// A committed damaged archive of `tests/data/zip/` (its README says how
/// each was made).
pub fn zip_data(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/zip")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The files `names` that stuffr's `zip args` over `tree` leaves (a split
/// set: `t.z01`, ..., `t.zip`), made in `flavour`.
pub fn zip_made_parts(
    flavour: &str,
    tree: &ZipTree,
    args: &[&str],
    names: &[&str],
) -> Vec<(String, Vec<u8>)> {
    use std::os::unix::process::CommandExt;
    let s = ScratchDir::unique("zip-parts");
    std::fs::create_dir_all(&*s).unwrap();
    tree.materialise(&s);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stuffr"));
    cmd.arg0("zip")
        .args(args)
        .current_dir(&*s)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("STUFFR_ZIP_FLAVOR", flavour)
        .stdin(Stdio::null());
    let o = output(&mut cmd).unwrap();
    assert!(o.status.success(), "zip {args:?}: {o:?}");
    names
        .iter()
        .map(|n| (n.to_string(), std::fs::read(s.join(n)).unwrap()))
        .collect()
}

/// The standard tree plus `big`, 140000 bytes of `random(_, 7)` (three
/// 64 KiB splits).
pub fn zip_split_tree() -> ZipTree {
    ZipTree::standard().file("big", random(140_000, 7))
}

/// `zip -X -s 64k s.zip big a.txt` over [`zip_split_tree`]: `s.z01`,
/// `s.z02`, `s.zip`, as `(name, bytes)`.
pub fn zip_split_set(flavour: &str) -> Vec<(String, Vec<u8>)> {
    zip_made_parts(
        flavour,
        &zip_split_tree(),
        &["-X", "-s", "64k", "s.zip", "big", "a.txt"],
        &["s.z01", "s.z02", "s.zip"],
    )
}

/// `tree` with the parts of `set` added, but those named in `leave_out`.
pub fn with_parts(mut tree: ZipTree, set: &[(String, Vec<u8>)], leave_out: &[&str]) -> ZipTree {
    for (n, b) in set {
        if !leave_out.contains(&n.as_str()) {
            tree = tree.file(n, b.clone());
        }
    }
    tree
}

/// Task 8: `-F` and `-FF` over the committed damaged archives and over
/// split sets (whole, a part missing, a part in another directory), with
/// the answers zip's questions take. Stdin always ends with an answer the
/// reference takes: at the end of standard input `-FF`'s questions spin
/// for ever in the C (ruling Z5, pinned stuffr-only).
pub fn zip_fix_matrix(flavour: &'static str) -> Vec<Case<'static>> {
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str], tree: ZipTree, stdin: &[u8]| {
        let mut c = zip_case("zip", args, tree);
        c.zip_flavour = Some(flavour);
        c.stdin = Some(stdin.to_vec());
        out.push(c);
    };
    let with = |name: &str| ZipTree::standard().file("in.zip", zip_data(name));
    let damaged = [
        "intact.zip",
        "cut-central.zip",
        "cut-data.zip",
        "bad-central.zip",
        "preamble.zip",
        "descriptors.zip",
        "descriptors-cut.zip",
        "comment-cut.zip",
        "junk.zip",
        "bad-version.zip",
    ];
    for name in damaged {
        add(&["-F", "in.zip", "--out", "f.zip"], with(name), b"");
        add(&["-F", "-v", "in.zip", "--out", "f.zip"], with(name), b"");
        // `y`: a single-disk archive, where the end record is missing
        add(&["-FF", "in.zip", "--out", "f.zip"], with(name), b"y\n");
        add(
            &["-FF", "-v", "in.zip", "--out", "f.zip"],
            with(name),
            b"y\n",
        );
        add(&["-FF", "-q", "in.zip", "--out", "f.zip"], with(name), b"");
    }
    // Apple's -FF copies the local extra field as zeros after its first NUL
    // (ruling Z19: Ubuntu's are heap garbage)
    if flavour == "apple" {
        add(
            &["-FF", "in.zip", "--out", "f.zip"],
            with("extra-cut.zip"),
            b"y\n",
        );
    }
    let cut = || with("cut-central.zip");
    // the questions about a part that is not there
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nq\n");
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\ne\n");
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\ns\nq\n");
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nz\n\n");
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nQ\n");
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nc\n\nq\n");
    add(
        &["-FF", "in.zip", "--out", "f.zip"],
        cut(),
        b"n\nc\nnodir/\nq\n",
    );
    add(&["-FF", "in.zip", "--out", "f.zip"], cut(), b"n\nx\nq\n");
    add(&["-FF", "nosuch.zip", "--out", "f.zip"], cut(), b"q\n");
    add(&["-F", "nosuch.zip", "--out", "f.zip"], cut(), b"");
    add(&["-F", "in.zip", "--out", "in.zip"], cut(), b"");
    add(
        &["-FF", "-b", "nodir", "in.zip", "--out", "f.zip"],
        cut(),
        b"y\n",
    );
    // split sets
    let set = zip_split_set(flavour);
    let parts = |leave: &[&str]| with_parts(zip_split_tree(), &set, leave);
    add(&["-F", "s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["-FF", "s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["-FF", "-v", "s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["-s", "0", "s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["-sv", "s.zip", "--out", "f.zip"], parts(&[]), b"");
    add(&["-U", "s.zip", "a.txt", "--out", "f.zip"], parts(&[]), b"");
    // (every answer list ends in one the reference takes: a reference
    // asking again at the end of standard input never stops)
    for answer in [&b"q\n"[..], b"s\n", b"Q\n", b"c\n\nq\n", b"\nq\n"] {
        add(
            &["-F", "s.zip", "--out", "f.zip"],
            parts(&["s.z02"]),
            answer,
        );
        add(
            &["-FF", "s.zip", "--out", "f.zip"],
            parts(&["s.z02"]),
            answer,
        );
        if answer != b"s\n" {
            // without -F, `s` is a name of a directory
            add(&["s.zip", "--out", "f.zip"], parts(&["s.z02"]), answer);
        }
    }
    add(
        &["-FF", "s.zip", "--out", "f.zip"],
        parts(&["s.z02"]),
        b"e\n",
    );
    add(
        &["-FF", "s.zip", "--out", "f.zip"],
        parts(&["s.z01"]),
        b"s\n",
    );
    add(
        &["-F", "s.zip", "--out", "f.zip"],
        parts(&["s.z01"]),
        b"s\n",
    );
    // quiet: the first part's open is an error, the next part's a question
    add(&["-q", "s.zip", "--out", "f.zip"], parts(&["s.z01"]), b"");
    add(
        &["-q", "s.zip", "--out", "f.zip"],
        parts(&["s.z02"]),
        b"q\n",
    );
    // the committed reference-made split set (README)
    let rset = || {
        ZipTree::standard()
            .file("split.z01", zip_data("split.z01"))
            .file("split.zip", zip_data("split.zip"))
    };
    let rmissing = || ZipTree::standard().file("split.zip", zip_data("split.zip"));
    add(&["-F", "split.zip", "--out", "f.zip"], rset(), b"");
    add(&["-FF", "split.zip", "--out", "f.zip"], rset(), b"");
    add(&["split.zip", "--out", "f.zip"], rset(), b"");
    for answer in [&b"q\n"[..], b"s\n"] {
        add(&["-F", "split.zip", "--out", "f.zip"], rmissing(), answer);
        add(&["-FF", "split.zip", "--out", "f.zip"], rmissing(), answer);
    }
    // the missing part in another directory: `c`, the directory, ENTER
    let mut moved = parts(&["s.z02"]);
    let z02 = set.iter().find(|(n, _)| n == "s.z02").unwrap().1.clone();
    moved = moved.file("sub/s.z02", z02);
    add(
        &["-F", "s.zip", "--out", "f.zip"],
        moved.clone(),
        b"c\nsub/\n\nq\n",
    );
    add(
        &["-FF", "s.zip", "--out", "f.zip"],
        moved,
        b"c\nsub/\n\nq\n",
    );
    out
}

/// Task 8: writing split archives (`-s`, `-sp`, `-sb`, `-sv`) and the
/// archives zip refuses to change.
pub fn zip_split_matrix(flavour: &'static str) -> Vec<Case<'static>> {
    let mut out: Vec<Case<'static>> = Vec::new();
    let mut add = |args: &[&'static str], tree: ZipTree, stdin: &[u8]| {
        let mut c = zip_case("zip", args, tree);
        c.zip_flavour = Some(flavour);
        c.stdin = Some(stdin.to_vec());
        out.push(c);
    };
    let big = || ZipTree::standard().file("big", random(200_000, 7));
    let enter = b"\n\n\n\n\n\n";
    for args in [
        &["-s", "64k", "t.zip", "big"][..],
        &["-s", "64k", "-sv", "t.zip", "big"],
        &["-s", "64k", "-sb", "t.zip", "big"],
        &["-s", "1m", "t.zip", "big"],
        &["-s", "1", "t.zip", "big"],
        &["-s", "64k", "t.zip", "a.txt", "b.txt"],
        &["-s", "64k", "t.zip", "a.txt", "big", "b.txt", "d"],
        &["-s", "64k", "-r", "t.zip", "."],
        &["-s", "64k", "-0", "t.zip", "big", "a.txt"],
        &["-s", "64k", "-fd", "t.zip", "big"],
        &["-s", "64k", "-fz", "t.zip", "big"],
        &["-s", "64k", "-X", "t.zip", "big", "a.txt"],
        &["-s", "64k", "-v", "t.zip", "big"],
        &["-s", "64k", "-dg", "-ds", "32k", "t.zip", "big"],
        &["-s", "64k", "-dv", "-dc", "t.zip", "big", "a.txt"],
        &["-s", "64k", "-b", "tmp", "t.zip", "big"],
        &["-s", "64k", "-sv", "-sb", "t.zip", "a.txt"],
        &["-sp", "t.zip", "a.txt", "big"],
        &["-s", "64k", "-sp", "t.zip", "big"],
        &["-s", "64k", "-sp", "-sb", "t.zip", "big"],
        &["-s", "64k", "-sp", "-sv", "t.zip", "big"],
        &[
            "-s", "64k", "-sp", "-sb", "-sv", "t.zip", "a.txt", "big", "b.txt",
        ],
        &["-s", "64k", "-s-", "t.zip", "big"],
        &["-s", "0", "t.zip", "big"],
    ] {
        add(args, big().dir("tmp"), enter);
    }
    // a comment after the splits (an empty first line would be Ubuntu's
    // heap overflow, `strcpy(p, "\r\n")` into one byte: not split-related)
    add(
        &["-s", "64k", "-z", "t.zip", "big"],
        big(),
        b"a comment\n.\n",
    );
    // -sp: the next split's directory, a directory or a bare name (the
    // archive's name must have a directory: without one zip's split names
    // index before their buffer)
    add(
        &["-s", "64k", "-sp", "w/t.zip", "big"],
        big().dir("w").dir("o"),
        b"o/\n\n\n\n",
    );
    add(
        &["-s", "64k", "-sp", "w/t.zip", "big"],
        big().dir("w"),
        b"x\n\n\n\n",
    );
    // archives zip refuses to change: an update or a deletion of a split
    // archive in place, a split to standard output, a grown split archive
    let set = zip_split_set(flavour);
    let parts = || with_parts(zip_split_tree(), &set, &[]);
    add(&["s.zip", "b.txt"], parts(), b"");
    add(&["-d", "s.zip", "a.txt"], parts(), b"");
    add(&["-g", "s.zip", "b.txt"], parts(), b"");
    add(&["-g", "s.zip", "b.txt", "--out", "f.zip"], parts(), b"");
    add(&["-s", "64k", "-", "big"], big(), b"");
    add(&["-sf", "s.zip"], parts(), b"");
    add(&["s.zip", "b.txt", "--out", "f.zip"], parts(), b"");
    add(
        &["-s", "64k", "s.zip", "b.txt", "--out", "f.zip"],
        parts(),
        b"",
    );
    add(
        &["-s", "64k", "t.zip", "big"],
        big().file("t.z01", b"old"),
        b"",
    );
    out
}
