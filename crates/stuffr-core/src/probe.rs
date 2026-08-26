//! Format detection and pipeline resolution.
//!
//! Streams have no filename, so extensions are a hint and never the decision.
//!
//! **Known Phase 0 limitation:** when an outer codec is detected on an input
//! with no path (stdin), the inner layer resolves to [`Chain::Raw`] because
//! there is no extension to consult. Phase 2 refines this by peeking at the
//! first decoded block. This is a documented boundary, not a bug.

use std::path::Path;

use crate::error::{Error, Result};
use crate::format::{FormatId, FormatKind};
use crate::registry::Registry;
use crate::source::{PeekSource, Source};

/// The detection window, per the spec.
pub const PROBE_LEN: usize = 4096;

/// Reads a bounded prefix without consuming it.
///
/// A seekable source is rewound; a pipe is wrapped in a [`PeekSource`] that
/// replays the prefix. Either way the caller still sees byte zero.
pub fn probe(mut src: Box<dyn Source>) -> Result<(Vec<u8>, Box<dyn Source>)> {
    if src.caps().seekable {
        let mut prefix = vec![0u8; PROBE_LEN];
        let seek = src.as_seek().expect("caps claimed seekable");
        let mut filled = 0;
        while filled < PROBE_LEN {
            match std::io::Read::read(seek, &mut prefix[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        prefix.truncate(filled);
        std::io::Seek::seek(seek, std::io::SeekFrom::Start(0))?;
        return Ok((prefix, src));
    }

    let peek = PeekSource::fill(src, PROBE_LEN)?;
    let prefix = peek.prefix().to_vec();
    Ok((prefix, Box::new(peek)))
}

/// A resolved decode pipeline.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Chain {
    /// A codec wrapping something else. Decode order: this codec, then `inner`.
    Codec { codec: FormatId, inner: Box<Chain> },
    /// A container of entries.
    Container { container: FormatId },
    /// Opaque bytes. The terminal case for a bare compressed file.
    Raw,
}

impl Chain {
    /// Human-readable form, innermost first: `"tar over gzip"`.
    pub fn describe(&self) -> String {
        match self {
            Chain::Raw => "raw".to_string(),
            Chain::Container { container } => container.to_string(),
            Chain::Codec { codec, inner } => match inner.as_ref() {
                Chain::Raw => codec.to_string(),
                other => format!("{} over {}", other.describe(), codec),
            },
        }
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty input".to_string();
    }
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lowercase extension components of a path, outermost last.
/// `"out.tar.gz"` → `["tar", "gz"]`.
fn extensions(path: &Path) -> Vec<String> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    name.split('.')
        .skip(1)
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Resolves the inner layer beneath an outer codec, using the path's remaining
/// extensions. `.tar.gz` → tar; `.tgz` → tar; `.gz` or no path → Raw.
fn inner_from_path(reg: &Registry, path: Option<&Path>, outer: FormatId) -> Chain {
    let Some(path) = path else {
        return Chain::Raw;
    };
    let exts = extensions(path);

    // Compound single extensions: "tgz" means tar-inside-gzip.
    if let Some(last) = exts.last() {
        if let Some(stripped) = last.strip_prefix('t') {
            if reg.by_extension(last) == Some(outer) && !stripped.is_empty() {
                if let Some(id) = reg.by_extension("tar") {
                    if reg.container(id).is_some() {
                        return Chain::Container { container: id };
                    }
                }
            }
        }
    }

    // Otherwise look one extension inwards.
    if exts.len() >= 2 {
        if let Some(id) = reg.by_extension(&exts[exts.len() - 2]) {
            if reg.container(id).is_some() {
                return Chain::Container { container: id };
            }
        }
    }
    Chain::Raw
}

/// Turns a path and/or a probed prefix into a concrete pipeline.
///
/// Magic wins; extensions break ties and act as the fallback. Failure names the
/// bytes actually seen so a misdetection is debuggable without library prints.
pub fn resolve_chain(reg: &Registry, path: Option<&Path>, prefix: &[u8]) -> Result<Chain> {
    let mut candidates = reg.match_magic(prefix);

    // More than one magic hit: let the extension disambiguate.
    if candidates.len() > 1 {
        if let Some(path) = path {
            if let Some(id) = extensions(path)
                .iter()
                .rev()
                .find_map(|e| reg.by_extension(e))
            {
                if candidates.contains(&id) {
                    candidates = vec![id];
                }
            }
        }
    }

    let outer = candidates.first().copied().or_else(|| {
        path.and_then(|p| extensions(p).iter().rev().find_map(|e| reg.by_extension(e)))
    });

    let Some(outer) = outer else {
        return Err(Error::UnknownFormat {
            seen: hex_prefix(prefix),
        });
    };

    let kind = if reg.container(outer).is_some() {
        FormatKind::Container
    } else if reg.codec(outer).is_some() {
        FormatKind::Codec
    } else {
        return Err(Error::FormatNotEnabled(outer));
    };

    Ok(match kind {
        FormatKind::Container => Chain::Container { container: outer },
        FormatKind::Codec => Chain::Codec {
            codec: outer,
            inner: Box::new(inner_from_path(reg, path, outer)),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{FormatId, FormatKind, FormatMeta, MagicRule};
    use crate::registry::Registry;
    use crate::source::{ReaderSource, Source};
    use crate::testing::{MockCodec, MockContainer};
    use std::io::Read;
    use std::path::Path;
    use std::sync::Arc;

    const GZIP: FormatId = FormatId::new("gzip");
    const TAR: FormatId = FormatId::new("tar");

    const GZIP_MAGIC: &[MagicRule] = &[MagicRule {
        offset: 0,
        bytes: &[0x1f, 0x8b],
        format: GZIP,
    }];
    const TAR_MAGIC: &[MagicRule] = &[MagicRule {
        offset: 257,
        bytes: b"ustar",
        format: TAR,
    }];

    fn registry() -> Registry {
        let mut r = Registry::new();
        r.register_codec(
            Arc::new(MockCodec),
            FormatMeta {
                id: GZIP,
                kind: FormatKind::Codec,
                extensions: &["gz", "tgz"],
                magics: GZIP_MAGIC,
            },
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta {
                id: TAR,
                kind: FormatKind::Container,
                extensions: &["tar"],
                magics: TAR_MAGIC,
            },
        );
        r
    }

    #[test]
    fn probe_does_not_consume_the_stream() {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(
            b"HEADERbody".to_vec(),
        )));
        let (prefix, mut rest) = probe(src).unwrap();
        assert_eq!(&prefix[..6], b"HEADER");

        let mut all = Vec::new();
        rest.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"HEADERbody", "the consumer must still see byte zero");
    }

    #[test]
    fn probe_reads_at_most_the_window() {
        let big = vec![b'x'; PROBE_LEN * 3];
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(big)));
        let (prefix, _) = probe(src).unwrap();
        assert_eq!(prefix.len(), PROBE_LEN);
    }

    #[test]
    fn magic_identifies_a_bare_codec_stream() {
        let r = registry();
        let chain = resolve_chain(&r, Some(Path::new("blob.gz")), &[0x1f, 0x8b, 0x08]).unwrap();
        assert_eq!(
            chain,
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Raw)
            }
        );
        assert_eq!(chain.describe(), "gzip");
    }

    #[test]
    fn a_double_extension_nests_the_container_inside_the_codec() {
        let r = registry();
        let chain = resolve_chain(&r, Some(Path::new("out.tar.gz")), &[0x1f, 0x8b, 0x08]).unwrap();
        assert_eq!(
            chain,
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Container { container: TAR })
            }
        );
        assert_eq!(chain.describe(), "tar over gzip");
    }

    #[test]
    fn a_codec_on_stdin_resolves_to_raw_inner() {
        // No path means no extension hint. Phase 2 refines this by peeking
        // after the first decoded block; until then Raw is the honest answer.
        let r = registry();
        let chain = resolve_chain(&r, None, &[0x1f, 0x8b, 0x08]).unwrap();
        assert_eq!(
            chain,
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Raw)
            }
        );
    }

    #[test]
    fn container_magic_resolves_directly() {
        let r = registry();
        let mut prefix = vec![0u8; 512];
        prefix[257..262].copy_from_slice(b"ustar");
        let chain = resolve_chain(&r, Some(Path::new("x.tar")), &prefix).unwrap();
        assert_eq!(chain, Chain::Container { container: TAR });
        assert_eq!(chain.describe(), "tar");
    }

    #[test]
    fn extension_is_the_fallback_when_magic_says_nothing() {
        let r = registry();
        let chain = resolve_chain(&r, Some(Path::new("mystery.tar")), b"no magic here").unwrap();
        assert_eq!(chain, Chain::Container { container: TAR });
    }

    #[test]
    fn tgz_single_extension_still_nests_tar_inside_gzip() {
        let r = registry();
        let chain = resolve_chain(&r, Some(Path::new("a.tgz")), &[0x1f, 0x8b]).unwrap();
        assert_eq!(
            chain,
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Container { container: TAR })
            }
        );
    }

    #[test]
    fn unknown_input_names_the_bytes_it_actually_saw() {
        // Debugging a misdetection must not require adding prints to the library.
        let r = registry();
        let err = resolve_chain(&r, None, &[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("de ad be ef"), "message was: {msg}");
        assert!(matches!(err, crate::Error::UnknownFormat { .. }));
    }

    #[test]
    fn unknown_empty_input_still_produces_a_usable_message() {
        let r = registry();
        let err = resolve_chain(&r, None, b"").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
