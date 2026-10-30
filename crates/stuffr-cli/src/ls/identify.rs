//! Strict identification of one file, for `stuffr ls`.
//!
//! A file is "openable" when [`stuffr::probe::identify_strict`] says so:
//! every layer's magic is confirmed by its format's own header check (or,
//! for a format with no magic at all — brotli today — named by the
//! extension), and the file's last 512 bytes
//! ([`stuffr::probe::TAIL_LEN`]) are not a foreign trailer (an Apple disk
//! image). At most [`PROBE_LEN`] bytes are read from the start and the tail
//! from the end; codec layers are decoded from the prefix alone, never from
//! the rest of the file.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use stuffr::probe::{Chain, PROBE_LEN, identify_strict, read_tail};
use stuffr::{DecodeOpts, Error, FileSource, Registry, Source};

/// The verdict for one file.
#[derive(Debug)]
pub enum Identified {
    Openable(Chain),
    NotOpenable,
}

/// Reads up to `PROBE_LEN` bytes from `f`.
fn read_prefix(mut f: impl Read) -> io::Result<Vec<u8>> {
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

/// macOS's `SF_DATALESS` `st_flags` bit: the file's data lives with a
/// cloud provider (iCloud "Optimise Mac Storage", a File Provider), and
/// reading any byte of it makes macOS download the whole file.
#[cfg(any(target_os = "macos", test))]
const SF_DATALESS: u32 = 0x4000_0000;

/// Whether `st_flags` mark a dataless placeholder.
#[cfg(any(target_os = "macos", test))]
fn flags_are_dataless(flags: u32) -> bool {
    flags & SF_DATALESS != 0
}

/// Whether `md` (followed, `fs::metadata`) is a macOS dataless placeholder,
/// which `stuffr ls` must never open: it counts as not openable, with no
/// warning. Always `false` elsewhere.
pub fn is_dataless(md: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        flags_are_dataless(md.st_flags())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = md;
        false
    }
}

/// Identifies `path` (following symlinks), reading at most [`PROBE_LEN`]
/// bytes from its start and [`stuffr::probe::TAIL_LEN`] from its end.
pub fn identify(reg: &Registry, path: &Path) -> io::Result<Identified> {
    let mut src = FileSource::from_file(File::open(path)?).map_err(into_io)?;
    identify_with_reader(reg, path, &mut src)
}

/// An error from the library's read helpers, back as the `io::Error` the
/// walk reports as a warning.
fn into_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// `identify` over an already-opened source for `path` (the path still
/// supplies the extension). Lets a test count the bytes read.
///
/// The tail is read first, as `probe` reads it, and leaves the source at
/// byte zero for the prefix. A file shorter than the tail has nothing to
/// look at there. The prefix's codec layers are decoded under the default
/// memory limit, the bound every verb given this file would use.
pub(crate) fn identify_with_reader(
    reg: &Registry,
    path: &Path,
    src: &mut dyn Source,
) -> io::Result<Identified> {
    let tail = read_tail(src).map_err(into_io)?;
    let prefix = read_prefix(&mut *src)?;
    let opts = DecodeOpts {
        memory_limit: Some(stuffr::default_memory_limit()),
        ..Default::default()
    };
    match identify_strict(reg, Some(path), &prefix, tail.as_deref(), &opts) {
        None | Some(Chain::Raw) => Ok(Identified::NotOpenable),
        Some(chain) => Ok(Identified::Openable(chain)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dataless_flag_is_bit_0x40000000_alone() {
        assert!(flags_are_dataless(0x4000_0000));
        // Alongside other flags (UF_HIDDEN 0x8000, SF_ARCHIVED 0x1_0000).
        assert!(flags_are_dataless(0x4000_0000 | 0x8000 | 0x1_0000));
        assert!(!flags_are_dataless(0));
        assert!(!flags_are_dataless(
            0x8000 | 0x1_0000 | 0x2000_0000 | 0x8000_0000
        ));
    }

    /// A real file on any test machine is not a placeholder.
    #[test]
    fn an_ordinary_file_is_not_dataless() {
        let md = std::fs::metadata(env!("CARGO_MANIFEST_DIR")).unwrap();
        assert!(!is_dataless(&md));
    }
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

    /// A real, empty gzip stream (`gzip -cn </dev/null`): a header alone
    /// is not something stuffr opens.
    const GZIP: &[u8] = &[
        0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// A real tar of one file, gzipped.
    fn tar_gz() -> Vec<u8> {
        use std::io::Write;
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_size(5);
        h.set_mode(0o644);
        tar.append_data(&mut h, "a.txt", &b"alpha"[..]).unwrap();
        let tar = tar.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap()
    }

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
        let p = d.file("x.tar.gz", &tar_gz());
        assert_eq!(describe(&p).as_deref(), Some("tar over gzip"));
    }

    /// The name no longer speaks for the inner layer when the decoded bytes
    /// can: a gzip holding no tar is a gzip, whatever its name says.
    #[test]
    fn tar_gz_named_empty_gzip_is_gzip() {
        let d = Dir::new();
        let p = d.file("x.tar.gz", GZIP);
        assert_eq!(describe(&p).as_deref(), Some("gzip"));
    }

    /// A gzip header with nothing after it decodes nothing before its end:
    /// not something stuffr opens.
    #[test]
    fn a_bare_gzip_header_is_not_openable() {
        let d = Dir::new();
        let p = d.file("blob.gz", &GZIP[..10]);
        assert_eq!(describe(&p), None);
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
