//! Compatibility links: when the binary is invoked under another tool's name
//! (through a symlink), it behaves as that tool, with that tool's flags,
//! messages and exit codes, not stuffr's.

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::ExitCode;

pub mod bzip2;
pub mod bzip2recover;
pub mod links;

/// A family of tools the binary can impersonate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Family {
    /// `bzip2`, `bunzip2`, `bzcat`.
    Bzip2,
}

/// Invoked name to family. The name is matched exactly, after the directory
/// is stripped.
const NAMES: &[(&str, Family)] = &[
    ("bzip2", Family::Bzip2),
    ("bunzip2", Family::Bzip2),
    ("bzcat", Family::Bzip2),
    ("bzip2recover", Family::Bzip2),
];

/// Every compatibility name, from the one table `family_for` also reads.
pub fn names() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| NAMES.iter().map(|&(n, _)| n).collect())
}

/// The family and canonical name for an `argv[0]`, or `None` when it is not a
/// compatibility name. Only the final path component counts, and on Windows a
/// trailing `.exe` is ignored.
pub fn family_for(argv0: &OsStr) -> Option<(Family, &'static str)> {
    let file = Path::new(argv0).file_name()?;
    let file = file.to_str()?;
    #[cfg(windows)]
    let file = file.strip_suffix(".exe").unwrap_or(file);
    NAMES
        .iter()
        .find(|(n, _)| *n == file)
        .map(|&(n, fam)| (fam, n))
}

/// Run the compatibility tool `args[0]` names, or return `None` when it names
/// none (the caller then behaves as `stuffr`). The tool gets the arguments
/// after `args[0]`; `bzip2recover`, which prints its `argv[0]` verbatim,
/// gets `args[0]` as well.
pub fn dispatch(args: Vec<OsString>) -> Option<ExitCode> {
    let (family, name) = family_for(args.first()?)?;
    let mut args = args.into_iter();
    let argv0 = args.next().unwrap_or_default();
    let rest = args.collect();
    Some(match family {
        // bzip2recover prints its argv[0] in full, so it gets it.
        Family::Bzip2 if name == "bzip2recover" => bzip2recover::run(argv0, rest),
        Family::Bzip2 => bzip2::run(name, rest),
    })
}

/// Run the compatibility tool `name` names in-process, without touching the
/// process: operands resolve against `dir`, `stdin` stands in for standard
/// input, and the exit code, standard output and standard error come back.
/// Neither stream is a terminal, the environment is not read and `SIGPIPE`
/// keeps its disposition. `None` when `name` is not a compatibility name.
/// Same code as [`dispatch`] below the process boundary; for the fuzz
/// target, not a stable interface.
#[doc(hidden)]
pub fn run_in(
    dir: &Path,
    name: &str,
    args: Vec<OsString>,
    stdin: &[u8],
) -> Option<(i32, Vec<u8>, Vec<u8>)> {
    let (family, canonical) = family_for(OsStr::new(name))?;
    Some(match family {
        Family::Bzip2 if canonical == "bzip2recover" => {
            let (code, err) = bzip2recover::run_in(dir, name.as_bytes(), &args);
            (code, Vec::new(), err)
        }
        Family::Bzip2 => bzip2::run_in(dir, canonical, &args, stdin),
    })
}

/// Whether stdin is a terminal.
pub(crate) fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Whether stdout is a terminal.
pub(crate) fn stdout_is_tty() -> bool {
    io::stdout().is_terminal()
}

/// Copy the access and modification times, permission bits and (where
/// permitted) owner in `meta` onto `to`. A refused `chown` (`EPERM`) is
/// ignored, as the reference tools do; every other failure is returned.
///
/// Takes metadata rather than a path because bzip2 saves its input's
/// metadata before reading it, so the access time it copies is the one from
/// before the read. `to` is opened for writing to set the times, so call
/// this before restricting `to`'s permissions any further.
pub(crate) fn copy_metadata_from(meta: &std::fs::Metadata, to: &Path) -> io::Result<()> {
    let mut times = std::fs::FileTimes::new();
    if let Ok(t) = meta.accessed() {
        times = times.set_accessed(t);
    }
    if let Ok(t) = meta.modified() {
        times = times.set_modified(t);
    }
    std::fs::File::options()
        .write(true)
        .open(to)?
        .set_times(times)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::os::unix::fs::chown(to, Some(meta.uid()), Some(meta.gid())) {
            Err(e) if e.kind() != io::ErrorKind::PermissionDenied => return Err(e),
            _ => {}
        }
    }
    // After `chown`, which may clear set-id bits.
    std::fs::set_permissions(to, meta.permissions())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_names_are_recognised_by_file_name_only() {
        use std::ffi::OsStr;
        assert_eq!(family_for(OsStr::new("bzip2")).map(|f| f.1), Some("bzip2"));
        assert_eq!(
            family_for(OsStr::new("/usr/local/bin/bunzip2")).map(|f| f.1),
            Some("bunzip2")
        );
        assert_eq!(family_for(OsStr::new("bzcat")).map(|f| f.1), Some("bzcat"));
        assert_eq!(
            family_for(OsStr::new("bzip2recover")).map(|f| f.1),
            Some("bzip2recover")
        );
        assert!(family_for(OsStr::new("stuffr")).is_none());
        assert!(family_for(OsStr::new("/x/bzip2/stuffr")).is_none());
        assert!(family_for(OsStr::new("bzip2x")).is_none());
        #[cfg(windows)]
        assert_eq!(
            family_for(OsStr::new("bzip2.exe")).map(|f| f.1),
            Some("bzip2")
        );
    }

    #[test]
    fn stuffr_itself_does_not_dispatch() {
        assert!(dispatch(vec!["stuffr".into(), "list".into()]).is_none());
    }

    #[test]
    fn dispatch_ignores_an_empty_argv() {
        assert!(dispatch(Vec::new()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_ignores_a_non_utf8_argv0() {
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(b"bzip2\xff").to_os_string();
        assert!(dispatch(vec![bad]).is_none());
        let bad = OsStr::from_bytes(b"/x/\xffbzip2").to_os_string();
        assert!(dispatch(vec![bad]).is_none());
    }

    /// `run_in` reaches both families, resolves operands against its
    /// directory and captures standard output.
    #[test]
    fn run_in_works_inside_its_directory() {
        let dir = std::env::temp_dir().join(format!("stuffr-run-in-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"hello hello hello\n").unwrap();
        let (code, out, err) = run_in(&dir, "bzip2", vec!["-k".into(), "a".into()], b"").unwrap();
        assert_eq!(
            (code, out.len()),
            (0, 0),
            "{}",
            String::from_utf8_lossy(&err)
        );
        let packed = std::fs::read(dir.join("a.bz2")).unwrap();
        assert!(packed.starts_with(b"BZh9"));
        let (code, out, _) = run_in(&dir, "bzcat", vec![], &packed).unwrap();
        assert_eq!((code, out.as_slice()), (0, &b"hello hello hello\n"[..]));
        let (code, out, err) = run_in(&dir, "bzip2recover", vec!["a.bz2".into()], b"").unwrap();
        assert_eq!(
            (code, out.len()),
            (0, 0),
            "{}",
            String::from_utf8_lossy(&err)
        );
        assert!(dir.join("rec00001a.bz2").exists());
        // A damaged stream from stdin: exit 2, stdin is never a terminal.
        let (code, _, err) = run_in(&dir, "bunzip2", vec![], b"BZh9garbage").unwrap();
        assert_eq!(code, 2, "{}", String::from_utf8_lossy(&err));
        assert!(run_in(&dir, "stuffr", vec![], b"").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Output past the sandbox's cap fails as a full disk does: exit 1.
    #[test]
    fn run_in_caps_what_a_run_writes() {
        let dir = std::env::temp_dir().join(format!("stuffr-run-in-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let big = vec![0u8; 9 * 1024 * 1024];
        let (code, packed, _) = run_in(&dir, "bzip2", vec![], &big).unwrap();
        assert_eq!(code, 0);
        let (code, out, err) = run_in(&dir, "bzcat", vec![], &packed).unwrap();
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 1, "{err}");
        // A write the budget cannot hold fails whole, so the output stops
        // within one buffered write (64 KiB) of the cap, never past it.
        let cap = 8 * 1024 * 1024;
        assert!(
            out.len() <= cap && out.len() > cap - 64 * 1024,
            "{}",
            out.len()
        );
        assert!(err.contains("I/O or other error"), "{err}");
        // `-t` writes nothing, but its decoding is charged to the same cap.
        let (code, out, err) = run_in(&dir, "bzip2", vec!["-t".into()], &packed).unwrap();
        let err = String::from_utf8_lossy(&err);
        assert_eq!((code, out.len()), (1, 0), "{err}");
        assert!(err.contains("I/O or other error"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_lists_the_table() {
        assert_eq!(names(), ["bzip2", "bunzip2", "bzcat", "bzip2recover"]);
    }

    #[test]
    fn copy_metadata_carries_mtime_and_permissions() {
        let dir = std::env::temp_dir().join(format!("stuffr-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"y").unwrap();
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&a)
            .unwrap()
            .set_modified(old)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        copy_metadata_from(&std::fs::metadata(&a).unwrap(), &b).unwrap();
        let (ma, mb) = (
            std::fs::metadata(&a).unwrap(),
            std::fs::metadata(&b).unwrap(),
        );
        assert_eq!(ma.modified().unwrap(), mb.modified().unwrap());
        assert_eq!(ma.permissions(), mb.permissions());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
