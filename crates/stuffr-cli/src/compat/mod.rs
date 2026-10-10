//! Compatibility links: when the binary is invoked under another tool's name
//! (through a symlink), it behaves as that tool, with that tool's flags,
//! messages and exit codes, not stuffr's.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

pub mod bzip2;
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
/// after `args[0]`.
pub fn dispatch(args: Vec<OsString>) -> Option<ExitCode> {
    let (family, name) = family_for(args.first()?)?;
    let rest = args.into_iter().skip(1).collect();
    Some(match family {
        Family::Bzip2 => bzip2::run(name, rest),
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

/// A compatibility program's identity, for its diagnostics.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Prog {
    /// The canonical invoked name, for example `"bunzip2"`.
    pub(crate) name: &'static str,
}

impl Prog {
    /// Write `"{name}: {msg}"` and a newline to stderr.
    pub(crate) fn err(&self, msg: fmt::Arguments) {
        let _ = writeln!(io::stderr().lock(), "{}: {}", self.name, msg);
    }
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
