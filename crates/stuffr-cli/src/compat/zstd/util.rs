//! util.c: the parts of zstd's utilities the family needs: the core
//! counts (R3), stat queries, human-readable sizes, `--filelist`, `-r`'s
//! expansion and `--output-dir-mirror`'s directories.

use std::fs::{self, Metadata};
use std::io::{self, Write};

use super::messages::{self as m, printf};
use crate::compat::host::{self, Host, strerror};

/// util.c: `UTIL_countLogicalCores` and `UTIL_countPhysicalCores`, read
/// once per run (R3). The real process reads the machine as util.c does on
/// its platform; a sandboxed run sees [`Cores::SANDBOX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cores {
    /// `UTIL_countLogicalCores()`.
    pub logical: u32,
    /// `UTIL_countPhysicalCores()`.
    pub physical: u32,
}

impl Cores {
    /// R3: the machine a sandboxed run sees.
    pub(crate) const SANDBOX: Cores = Cores {
        logical: 8,
        physical: 4,
    };

    /// The machine's counts, as util.c's `UTIL_countCores` reads them.
    pub(crate) fn detect() -> Cores {
        let (logical, physical) = count_cores();
        Cores {
            logical: logical.max(1),
            physical: physical.max(1),
        }
    }

    /// zstdcli.c: `ZSTDCLI_NBTHREADS_DEFAULT`, `MAX(1, MIN(4,
    /// UTIL_countLogicalCores() / 4))`.
    pub(crate) fn default_workers(self) -> u32 {
        (self.logical / 4).clamp(1, 4)
    }
}

/// util.c (`__APPLE__`): `sysctlbyname("hw.logicalcpu")` and
/// `"hw.physicalcpu"`, 1 when the entry is missing.
#[cfg(target_vendor = "apple")]
fn count_cores() -> (u32, u32) {
    fn read(name: &std::ffi::CStr) -> u32 {
        let mut n: i32 = 0;
        let mut size = std::mem::size_of::<i32>();
        // SAFETY: `name` is NUL-terminated, `n` is valid for `size` bytes,
        // and no new value is set.
        let r = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut n as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 && n > 0 { n as u32 } else { 1 }
    }
    (read(c"hw.logicalcpu"), read(c"hw.physicalcpu"))
}

/// util.c (`__linux__`): `sysconf(_SC_NPROCESSORS_ONLN)`, and for the
/// physical count that divided by `/proc/cpuinfo`'s `siblings` / `cpu
/// cores` ratio when hyperthreading shows.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online <= 0 {
        return (1, 1);
    }
    let logical = online as u32;
    let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") else {
        return (logical, logical);
    };
    (logical, physical_from_cpuinfo(logical, &info))
}

/// util.c's `/proc/cpuinfo` walk: the last `siblings` and `cpu cores`
/// values (`atoi` of the text after `:`); a line without `:` stops the walk
/// and keeps `numCores`.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn physical_from_cpuinfo(online: u32, info: &str) -> u32 {
    fn atoi(s: &str) -> i64 {
        let s = s.trim_start();
        let (neg, digits) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let n = digits
            .bytes()
            .take_while(u8::is_ascii_digit)
            .fold(0i64, |n, b| {
                n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
            });
        if neg { -n } else { n }
    }
    let (mut siblings, mut cpu_cores) = (0i64, 0i64);
    for line in info.lines() {
        // fgets(buff, 80): a longer line is read in pieces, but the keys
        // only ever start a line, so only its first piece can match.
        let line = line.get(..79).unwrap_or(line);
        for (key, slot) in [("siblings", &mut siblings), ("cpu cores", &mut cpu_cores)] {
            if line.starts_with(key) {
                match line.find(':') {
                    Some(at) => *slot = atoi(&line[at + 1..]),
                    None => return online,
                }
            }
        }
    }
    let ratio = if siblings != 0 && cpu_cores != 0 && siblings > cpu_cores {
        siblings / cpu_cores
    } else {
        1
    };
    if ratio != 0 && i64::from(online) > ratio {
        (i64::from(online) / ratio) as u32
    } else {
        online
    }
}

/// util.c (the other POSIX systems): `sysconf(_SC_NPROCESSORS_ONLN)` for
/// both.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let n = if n > 0 { n as u32 } else { 1 };
    (n, n)
}

/// Elsewhere (Windows: util.c asks `GetLogicalProcessorInformation`): the
/// standard library's count for both.
#[cfg(not(unix))]
fn count_cores() -> (u32, u32) {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    (n, n)
}

// ---- util.c: files and names ----

/// `UTIL_FILESIZE_UNKNOWN`.
pub(crate) const FILESIZE_UNKNOWN: u64 = u64::MAX;

/// util.c: `MAX_FILE_OF_FILE_NAMES_SIZE`, the largest `--filelist` file.
const MAX_FILE_OF_FILE_NAMES_SIZE: u64 = 50 << 20;

/// util.c: `DIR_DEFAULT_MODE`.
#[cfg(unix)]
const DIR_DEFAULT_MODE: u32 = 0o755;

/// platform.h: `PATH_SEP`.
#[cfg(windows)]
pub(crate) const PATH_SEP: u8 = b'\\';
/// platform.h: `PATH_SEP`.
#[cfg(not(windows))]
pub(crate) const PATH_SEP: u8 = b'/';

/// `UTIL_stat`: `stat(2)`, following a final symbolic link.
pub(crate) fn stat(host: &Host, name: &[u8]) -> io::Result<Metadata> {
    fs::metadata(host.path(name))
}

/// `UTIL_isRegularFile`.
pub(crate) fn is_regular_file(host: &Host, name: &[u8]) -> bool {
    stat(host, name).is_ok_and(|m| m.is_file())
}

/// `UTIL_isDirectory`.
pub(crate) fn is_directory(host: &Host, name: &[u8]) -> bool {
    stat(host, name).is_ok_and(|m| m.is_dir())
}

/// `UTIL_isFIFOStat`.
pub(crate) fn is_fifo_stat(m: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_fifo()
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        false
    }
}

/// `UTIL_isBlockDevStat`.
pub(crate) fn is_block_dev_stat(m: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_block_device()
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        false
    }
}

/// `UTIL_isLink`: `lstat(2)` says a symbolic link (never on Windows, as
/// util.c).
pub(crate) fn is_link(host: &Host, name: &[u8]) -> bool {
    cfg!(unix) && fs::symlink_metadata(host.path(name)).is_ok_and(|m| m.file_type().is_symlink())
}

/// `UTIL_isFIFO`.
pub(crate) fn is_fifo(host: &Host, name: &[u8]) -> bool {
    stat(host, name).is_ok_and(|m| is_fifo_stat(&m))
}

/// `UTIL_getFileSize`: a regular file's size (following links), else
/// [`FILESIZE_UNKNOWN`].
pub(crate) fn file_size(host: &Host, name: &[u8]) -> u64 {
    stat(host, name).map_or(FILESIZE_UNKNOWN, |m| file_size_stat(&m))
}

/// `UTIL_getFileSizeStat`.
pub(crate) fn file_size_stat(m: &Metadata) -> u64 {
    if m.is_file() {
        m.len()
    } else {
        FILESIZE_UNKNOWN
    }
}

/// `UTIL_isSameFileStat`: the same device and inode (the same name, off
/// unix).
pub(crate) fn is_same_file_stat(n1: &[u8], n2: &[u8], m1: &Metadata, m2: &Metadata) -> bool {
    host::same_file(m1, m2).unwrap_or(n1 == n2)
}

/// `UTIL_isSameFile`.
pub(crate) fn is_same_file(host: &Host, n1: &[u8], n2: &[u8]) -> bool {
    match (stat(host, n1), stat(host, n2)) {
        (Ok(a), Ok(b)) => is_same_file_stat(n1, n2, &a, &b),
        _ => false,
    }
}

/// `UTIL_getFileExtension`: from the last `.`, or empty when there is none
/// or it starts the name.
pub(crate) fn file_extension(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'.') {
        Some(at) if at > 0 => &name[at..],
        _ => b"",
    }
}

/// `UTIL_isCompressedFile`.
pub(crate) fn is_compressed_file(name: &[u8], extensions: &[&str]) -> bool {
    let ext = file_extension(name);
    extensions.iter().any(|e| e.as_bytes() == ext)
}

/// `UTIL_HumanReadableSize_t`: a size scaled for display, printed with
/// `%.*f%s` (`precision`, `value`, `suffix`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Hrs {
    pub value: f64,
    pub suffix: &'static str,
    pub precision: usize,
}

impl Hrs {
    /// `%.*f%s`.
    pub(crate) fn plain(&self) -> String {
        format!("{:.*}{}", self.precision, self.value, self.suffix)
    }

    /// `%<width>.*f`, the value alone.
    pub(crate) fn value_w(&self, width: usize) -> String {
        format!("{:>width$.*}", self.precision, self.value)
    }
}

/// `UTIL_makeHumanReadableSize`, at `g_utilDisplayLevel` `util_level`.
pub(crate) fn human_size(size: u64, util_level: i32) -> Hrs {
    if util_level > 3 {
        if size >= 1 << 53 {
            return Hrs {
                value: size as f64 / (1u64 << 20) as f64,
                suffix: " MiB",
                precision: 2,
            };
        }
        return Hrs {
            value: size as f64,
            suffix: " B",
            precision: 0,
        };
    }
    let (value, suffix) = if size >= 1 << 60 {
        (size as f64 / (1u64 << 60) as f64, " EiB")
    } else if size >= 1 << 50 {
        (size as f64 / (1u64 << 50) as f64, " PiB")
    } else if size >= 1 << 40 {
        (size as f64 / (1u64 << 40) as f64, " TiB")
    } else if size >= 1 << 30 {
        (size as f64 / (1u64 << 30) as f64, " GiB")
    } else if size >= 1 << 20 {
        (size as f64 / (1u64 << 20) as f64, " MiB")
    } else if size >= 1 << 10 {
        (size as f64 / (1u64 << 10) as f64, " KiB")
    } else {
        (size as f64, " B")
    };
    let precision = if value >= 100.0 || value as u64 == size {
        0
    } else if value >= 10.0 {
        1
    } else if value > 1.0 {
        2
    } else {
        3
    };
    Hrs {
        value,
        suffix,
        precision,
    }
}

/// `UTIL_DISPLAYLEVEL`: `fmt` on standard error at `g_utilDisplayLevel`
/// `level` or above.
fn util_display(util_level: i32, level: i32, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
    if util_level >= level {
        printf(err, fmt, args);
    }
}

/// `UTIL_createFileNamesTable_fromFileName` (`--filelist`): the names in
/// `name`, one per line, or `None` when it is not a regular file, is larger
/// than 50 MiB, cannot be read (said with `perror`'s text) or names nothing.
/// Lines are read as `fgets` reads them: a line ends at `\n`, which is
/// dropped; a name ends at its first NUL; a line whose name is empty before
/// any `\n` (it starts with a NUL) ends the list.
pub(crate) fn names_from_file(
    host: &Host,
    name: &[u8],
    util_level: i32,
    err: &mut dyn Write,
) -> Option<Vec<Vec<u8>>> {
    let meta = stat(host, name).ok().filter(|m| m.is_file())?;
    if file_size_stat(&meta) > MAX_FILE_OF_FILE_NAMES_SIZE {
        return None;
    }
    let data = match fs::read(host.path(name)) {
        Ok(d) => d,
        Err(e) => {
            util_display(util_level, 1, err, m::PERROR_READ_LINES, &[&strerror(&e)]);
            return None;
        }
    };
    let mut names = Vec::new();
    for line in data.split_inclusive(|&b| b == b'\n') {
        let line = line.split(|&b| b == 0).next().unwrap_or_default();
        if line.is_empty() {
            break;
        }
        names.push(line.strip_suffix(b"\n").unwrap_or(line).to_vec());
    }
    (!names.is_empty()).then_some(names)
}

/// `UTIL_expandFNT` (`-r`): each directory replaced by the files under it,
/// in `readdir` order, depth first; every other name kept.
pub(crate) fn expand_names(
    host: &Host,
    names: Vec<Vec<u8>>,
    follow_links: bool,
    util_level: i32,
    err: &mut dyn Write,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for name in names {
        if is_directory(host, &name) {
            prepare_file_list(host, &name, &mut out, follow_links, util_level, err);
        } else {
            out.push(name);
        }
    }
    out
}

/// util.c (POSIX): `UTIL_prepareFileList`.
fn prepare_file_list(
    host: &Host,
    dir: &[u8],
    out: &mut Vec<Vec<u8>>,
    follow_links: bool,
    util_level: i32,
    err: &mut dyn Write,
) {
    let entries = match fs::read_dir(host.path(dir)) {
        Ok(e) => e,
        Err(e) => {
            util_display(
                util_level,
                1,
                err,
                m::CANNOT_OPEN_DIR,
                &[dir, &strerror(&e)],
            );
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                util_display(util_level, 1, err, m::READDIR_ERROR, &[dir, &strerror(&e)]);
                return;
            }
        };
        let mut path = dir.to_vec();
        path.push(b'/');
        path.extend_from_slice(&os_bytes(&entry.file_name()));
        if !follow_links && is_link(host, &path) {
            util_display(util_level, 2, err, m::UTIL_SYMLINK_IGNORED, &[&path]);
            continue;
        }
        if is_directory(host, &path) {
            prepare_file_list(host, &path, out, follow_links, util_level, err);
        } else {
            out.push(path);
        }
    }
}

/// A name's bytes.
fn os_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

// ---- util.c: --output-dir-mirror ----

/// util.c: pathnameHas2Dots: a whole `..` path component.
fn has_two_dots(p: &[u8]) -> bool {
    p.split(|&b| b == PATH_SEP).any(|c| c == b"..")
}

/// util.c: trimLeadingCurrentDirConst.
fn trim_current_dir(p: &[u8]) -> &[u8] {
    match p {
        [b'.', s, rest @ ..] if *s == PATH_SEP => rest,
        _ => p,
    }
}

/// util.c: trimPath: a leading `./`, then a leading `/`.
fn trim_path(p: &[u8]) -> &[u8] {
    let p = trim_current_dir(p);
    match p.first() {
        Some(&b) if b == PATH_SEP => &p[1..],
        _ => p,
    }
}

/// util.c: mallocAndJoin2Dir.
fn join_2_dir(d1: &[u8], d2: &[u8]) -> Vec<u8> {
    let mut v = d1.to_vec();
    if !d1.is_empty() && d1.last() != Some(&PATH_SEP) {
        v.push(PATH_SEP);
    }
    v.extend_from_slice(d2);
    v
}

/// util.c: convertPathnameToDirName, as the C code does it: it looks for
/// trailing separators only at `pathname[len]` (the terminator), so none
/// are ever removed; then everything from the last separator is cut, and a
/// name without one becomes `.`.
fn dir_name(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return Vec::new();
    }
    match p.iter().rposition(|&b| b == PATH_SEP) {
        Some(at) => p[..at].to_vec(),
        None => b".".to_vec(),
    }
}

/// `UTIL_createMirroredDestDirName`: the directory under `root` where
/// `src`'s output goes, or `None` for a name with a `..` component.
pub(crate) fn mirrored_dest_dir(src: &[u8], root: &[u8]) -> Option<Vec<u8>> {
    if has_two_dots(src) {
        return None;
    }
    Some(dir_name(&join_2_dir(root, trim_path(src))))
}

/// `UTIL_mirrorSourceFilesDirectories`: create `root` and, below it, each
/// input's directory with the source directory's mode.
pub(crate) fn mirror_source_dirs(host: &Host, names: &[Vec<u8>], root: &[u8], err: &mut dyn Write) {
    let mut dirs: Vec<Vec<u8>> = names
        .iter()
        .filter(|n| !has_two_dots(n))
        .map(|n| dir_name(n))
        .collect();
    if dirs.is_empty() {
        return;
    }
    let _ = make_dir(host, root, None, err);
    // makeUniqueMirroredDestDirs: sorted by the trimmed path; a directory
    // that is the parent of (or the same as) the next is skipped, the
    // deepest of a chain kept.
    dirs.sort_by(|a, b| trim_path(a).cmp(trim_path(b)));
    let mut unique: Vec<Vec<u8>> = Vec::new();
    for (i, d) in dirs.iter().enumerate() {
        if i == 0 {
            unique.push(d.clone());
            continue;
        }
        let prev = trim_path(&dirs[i - 1]);
        let cur = trim_path(d);
        let parent = prev.len() <= cur.len()
            && (cur.get(prev.len()).is_none_or(|&b| b == PATH_SEP))
            && cur.starts_with(prev);
        if parent {
            *unique.last_mut().expect("one pushed") = d.clone();
        } else {
            unique.push(d.clone());
        }
    }
    for d in unique {
        mirror_src_dir_recursive(host, &d, root, err);
    }
}

/// util.c: mirrorSrcDirRecursive: each prefix of `src` ending before a
/// separator, then `src` itself, mirrored under `root`.
fn mirror_src_dir_recursive(host: &Host, src: &[u8], root: &[u8], err: &mut dyn Write) {
    let skip = src.len() - trim_current_dir(src).len();
    let mut at = skip;
    while let Some(off) = src[at..].iter().position(|&b| b == PATH_SEP) {
        let sp = at + off;
        if sp != at && mirror_src_dir(host, &src[..sp], root, err).is_err() {
            return;
        }
        at = sp + 1;
    }
    let _ = mirror_src_dir(host, src, root, err);
}

/// util.c: mirrorSrcDir.
fn mirror_src_dir(host: &Host, src: &[u8], root: &[u8], err: &mut dyn Write) -> Result<(), ()> {
    let new_dir = join_2_dir(root, trim_path(src));
    let mode = dir_mode(host, src, err);
    make_dir(host, &new_dir, mode, err)
}

/// util.c: getDirMode: the directory's mode, else 0755 with a message.
fn dir_mode(host: &Host, dir: &[u8], err: &mut dyn Write) -> Option<u32> {
    match stat(host, dir) {
        Err(e) => {
            printf(err, m::DIR_STAT_FAILED, &[dir, &strerror(&e)]);
            None
        }
        Ok(m) if !m.is_dir() => {
            printf(err, m::EXPECTED_DIRECTORY, &[dir]);
            None
        }
        Ok(m) => Some(mode_of(&m)),
    }
}

fn mode_of(m: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        0o755
    }
}

/// util.c: makeDir: `mkdir(dir, mode)` (`None`: `DIR_DEFAULT_MODE`), an
/// existing name being success.
fn make_dir(host: &Host, dir: &[u8], mode: Option<u32>, err: &mut dyn Write) -> Result<(), ()> {
    #[cfg(unix)]
    let b = {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = fs::DirBuilder::new();
        b.mode(mode.unwrap_or(DIR_DEFAULT_MODE));
        b
    };
    #[cfg(not(unix))]
    let b = {
        let _ = mode;
        fs::DirBuilder::new()
    };
    match b.create(host.path(dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => {
            printf(err, m::MKDIR_FAILED, &[dir, &strerror(&e)]);
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_worker_count_is_a_quarter_of_the_logical_cores_within_1_to_4() {
        let w = |logical| {
            Cores {
                logical,
                physical: 1,
            }
            .default_workers()
        };
        assert_eq!([w(1), w(4), w(8), w(12), w(16), w(64)], [1, 1, 2, 3, 4, 4]);
        assert_eq!(Cores::SANDBOX.default_workers(), 2);
    }

    #[test]
    fn detected_counts_are_positive() {
        let c = Cores::detect();
        assert!(c.logical >= 1 && c.physical >= 1, "{c:?}");
    }

    #[test]
    fn human_sizes_scale_as_util_c_scales_them() {
        // `%.*f%s`, and `%6.*f` (the value right-aligned in six columns).
        let h = |n, l| {
            let h = human_size(n, l);
            let w = h.value_w(6);
            assert!(w.len() >= 6 && w.trim_start() == format!("{:.*}", h.precision, h.value));
            h.plain()
        };
        assert_eq!(h(0, 2), "0 B");
        assert_eq!(h(1023, 2), "1023 B");
        assert_eq!(h(1760, 2), "1.72 KiB");
        // Exactly 1 is not above 1: three decimals.
        assert_eq!(h(1024, 2), "1.000 KiB");
        assert_eq!(h(20 << 20, 2), "20.0 MiB");
        assert_eq!(h((20 << 20) + 1, 2), "20.0 MiB");
        assert_eq!(h(150 << 10, 2), "150 KiB");
        assert_eq!(h(1760, 4), "1760 B");
        assert_eq!(h(1 << 53, 4), "8589934592.00 MiB");
    }

    #[test]
    fn a_file_list_is_read_as_fgets_reads_it() {
        let dir = std::env::temp_dir().join(format!("stuffr-zstd-util-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let host = Host::Real;
        let list = |content: &[u8]| {
            let p = dir.join("list");
            fs::write(&p, content).unwrap();
            let mut err = Vec::new();
            let r = names_from_file(&host, p.to_str().unwrap().as_bytes(), 2, &mut err);
            assert!(err.is_empty());
            r
        };
        let v = |names: &[&str]| Some(names.iter().map(|n| n.as_bytes().to_vec()).collect());
        assert_eq!(list(b"a\nb\n"), v(&["a", "b"]));
        assert_eq!(list(b"a\nb"), v(&["a", "b"]));
        assert_eq!(list(b"a\n\nb\n"), v(&["a", "", "b"]));
        assert_eq!(list(b"a\r\n"), v(&["a\r"]));
        assert_eq!(list(b"a\0x\nb\n"), v(&["a", "b"]));
        assert_eq!(list(b"a\n\0b\nc\n"), v(&["a"]));
        assert_eq!(list(b""), None);
        let mut err = Vec::new();
        assert_eq!(
            names_from_file(&host, dir.to_str().unwrap().as_bytes(), 2, &mut err),
            None
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirrored_names_keep_the_source_directories() {
        let m = |src: &str, root: &str| {
            mirrored_dest_dir(src.as_bytes(), root.as_bytes())
                .map(|v| String::from_utf8(v).unwrap())
        };
        assert_eq!(m("a", "o").as_deref(), Some("o"));
        assert_eq!(m("d/a", "o").as_deref(), Some("o/d"));
        assert_eq!(m("./d/a", "o/").as_deref(), Some("o/d"));
        assert_eq!(m("/abs/d/a", "o").as_deref(), Some("o/abs/d"));
        assert_eq!(m("d/../a", "o"), None);
        assert_eq!(m("..", "o"), None);
        assert_eq!(m("d/..x/a", "o").as_deref(), Some("o/d/..x"));
    }

    #[test]
    fn cpuinfo_divides_by_the_hyperthreading_ratio() {
        let ht = "processor\t: 0\nsiblings\t: 8\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(16, ht), 8);
        assert_eq!(
            physical_from_cpuinfo(2, ht),
            2,
            "online not above the ratio"
        );
        assert_eq!(physical_from_cpuinfo(4, "processor\t: 0\n"), 4);
        assert_eq!(physical_from_cpuinfo(4, "siblings 8\n"), 4, "no colon");
        let no_ht = "siblings\t: 4\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(4, no_ht), 4);
    }
}
