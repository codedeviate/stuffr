//! Magic-only identification of one file, for `stuffr ls`.
//!
//! A file is "openable" when its first `PROBE_LEN` bytes match a registered
//! format's magic. The extension is consulted only for a format that has no
//! magic at all (brotli today). Nothing is ever decoded.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use stuffr::probe::{Chain, PROBE_LEN, resolve_chain};
use stuffr::{Error, Registry};

/// The verdict for one file.
#[derive(Debug)]
pub enum Identified {
    Openable(Chain),
    NotOpenable,
}

/// Reads up to `PROBE_LEN` bytes of `path` (following symlinks).
fn read_prefix(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; PROBE_LEN];
    let mut n = 0;
    while n < PROBE_LEN {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(n);
    Ok(buf)
}

/// The outermost extension's format, when that format has no magic.
fn magicless_by_extension(reg: &Registry, path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    reg.by_extension(ext).is_some_and(|id| !reg.has_magic(id))
}

pub fn identify(reg: &Registry, path: &Path) -> io::Result<Identified> {
    let prefix = read_prefix(path)?;
    let worth_resolving = !reg.match_magic(&prefix).is_empty() || magicless_by_extension(reg, path);
    if !worth_resolving {
        return Ok(Identified::NotOpenable);
    }
    match resolve_chain(reg, Some(path), &prefix) {
        Ok(Chain::Raw) => Ok(Identified::NotOpenable),
        Ok(chain) => Ok(Identified::Openable(chain)),
        Err(
            Error::AmbiguousFormat { .. }
            | Error::FormatNotEnabled(_)
            | Error::UnknownFormat { .. },
        ) => Ok(Identified::NotOpenable),
        Err(Error::Io(e)) => Err(e),
        Err(other) => Err(io::Error::other(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch directory `stuffr-ls-<pid>-<n>` that removes itself.
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Dir {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let mut p = std::env::temp_dir();
            p.push(format!(
                "stuffr-ls-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const GZIP: &[u8] = &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];

    fn describe(path: &Path) -> Option<String> {
        match identify(stuffr::registry(), path).unwrap() {
            Identified::Openable(c) => Some(c.describe()),
            Identified::NotOpenable => None,
        }
    }

    #[test]
    fn gzip_without_extension_is_openable() {
        let d = Dir::new();
        let p = d.file("blob", GZIP);
        assert_eq!(describe(&p).as_deref(), Some("gzip"));
    }

    #[test]
    fn tar_gz_named_reads_tar_over_gzip() {
        let d = Dir::new();
        let p = d.file("x.tar.gz", GZIP);
        assert_eq!(describe(&p).as_deref(), Some("tar over gzip"));
    }

    #[test]
    fn html_named_zip_is_not_openable() {
        let d = Dir::new();
        let p = d.file("page.zip", b"<html><body>not a zip</body></html>");
        assert_eq!(describe(&p), None);
    }

    #[test]
    fn br_by_extension_is_openable() {
        use stuffr::ops::{self, CompressOpts, Input, Output};
        let d = Dir::new();
        let src = d.file("plain.txt", b"hello hello hello hello brotli");
        let dst = d.0.join("out.br");
        ops::compress(
            Input::Path(src),
            Output::Path(dst.clone()),
            &CompressOpts::default(),
        )
        .unwrap();
        assert_eq!(describe(&dst).as_deref(), Some("brotli"));
    }

    #[test]
    fn plain_text_is_not_openable() {
        let d = Dir::new();
        let p = d.file("notes.txt", b"just some text\n");
        assert_eq!(describe(&p), None);
    }

    #[test]
    fn empty_file_is_not_openable() {
        let d = Dir::new();
        let p = d.file("empty", b"");
        assert_eq!(describe(&p), None);
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let d = Dir::new();
        let e = identify(stuffr::registry(), &d.0.join("nope")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
