//! Format detection and pipeline resolution.
//!
//! Streams have no filename, so extensions are a hint and never the decision.
//!
//! [`resolve_chain`] is the single-layer resolution: outer format only, with
//! the inner layer decided from the path's remaining extensions when one is
//! given ([`inner_from_path`]) and [`Chain::Raw`] otherwise. [`resolve_chain_deep`]
//! closes that gap: whenever the outer layer is a codec and the inner layer
//! is still [`Chain::Raw`] — no path at all (stdin), or a path whose
//! extensions ran out — it decodes that layer, peeks [`PROBE_LEN`] of the
//! *decoded* bytes, and resolves again — recursively, bounded by
//! [`MAX_CHAIN_DEPTH`] on both routes, so that neither a piped stream nor a
//! misleadingly-named file can turn re-probing a decoded stream into an
//! unbounded decompression-nesting attack. Either way the source it returns
//! is already decoded through every codec layer named in the resolved
//! `Chain`, so a caller never has to guess which route produced it.

use std::path::Path;

use crate::archive::DecodeOpts;
use crate::error::{Error, Result};
use crate::format::{FormatId, FormatKind};
use crate::registry::Registry;
use crate::source::{PeekSource, Source};

/// The detection window, per the spec.
pub const PROBE_LEN: usize = 4096;

/// Maximum layers when re-probing a decoded stream.
///
/// Four, chosen against real shapes: `.tar.gz` is depth 2 and `.tar.gz.gz` at
/// depth 3 is already pathological, so this leaves headroom without admitting
/// a decompression-nesting bomb. `Chain` is recursive, so the bound lives at
/// the resolution site rather than in the type.
pub const MAX_CHAIN_DEPTH: usize = 4;

/// Reads a bounded prefix without consuming it.
///
/// A seekable source is rewound; a pipe is wrapped in a [`PeekSource`] that
/// replays the prefix. Either way the caller still sees byte zero.
pub fn probe(mut src: Box<dyn Source>) -> Result<(Vec<u8>, Box<dyn Source>)> {
    if src.caps().seekable {
        let mut prefix = vec![0u8; PROBE_LEN];
        // `caps().seekable` is the `Source`'s own claim; `as_seek()` is a
        // second, independent method on the same trait, and `Source` is
        // public — a third-party codec (Phase 2+) can implement one without
        // honouring the other. Trusting the claim with `.expect(..)` turned a
        // buggy-but-foreign `Source` impl into a panic reachable through this
        // crate's own public `probe`; surfacing it as a typed error instead
        // lets a caller match on it same as any other seek failure. There is
        // no format to name yet at this stage of detection, so the sentinel
        // id below is a placeholder, not a registered format.
        let Some(seek) = src.as_seek() else {
            return Err(Error::NotSeekable {
                format: FormatId::new("<probe>"),
            });
        };
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
#[non_exhaustive]
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
    /// The container this chain resolves to, if any, at ANY depth.
    ///
    /// `Some(tar)` for `tar over gzip` as well as for a bare `tar`: however
    /// many codec layers sit above it, the entries live in a container, and a
    /// caller that has not OPENED that container cannot speak for its
    /// fidelity. That is the whole use — `ops::inspect` identifies a stream
    /// WITHOUT decoding it, so it never opens the container and must not
    /// report a fidelity conclusion it did not reach. See
    /// `ops::Inspection::fidelity_evaluated`.
    ///
    /// The `_` arm covers [`Chain::Raw`] and anything added later: `Chain` is
    /// `#[non_exhaustive]`, and "no container" is the right answer for a
    /// shape this method does not recognise, since the caller's only use of
    /// `Some` is to withhold a claim.
    pub fn container(&self) -> Option<FormatId> {
        match self {
            Chain::Container { container } => Some(*container),
            Chain::Codec { inner, .. } => inner.container(),
            _ => None,
        }
    }

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

    // `.tgz` and friends: one extension meaning "tar inside <codec>", spelled
    // as "t" + the codec's own extension. The lookup uses the STRIPPED suffix,
    // not the whole string — checking the whole string would only work if every
    // codec also registered its compound alias, and one that forgot would
    // silently resolve `.tbz2` to Raw instead of tar-over-bzip2.
    if let Some(last) = exts.last()
        && let Some(stripped) = last.strip_prefix('t')
        && !stripped.is_empty()
        && reg.by_extension(stripped) == Some(outer)
        && let Some(id) = reg.by_extension("tar")
        && reg.container(id).is_some()
    {
        return Chain::Container { container: id };
    }

    // Otherwise look one extension inwards.
    if exts.len() >= 2
        && let Some(id) = reg.by_extension(&exts[exts.len() - 2])
        && reg.container(id).is_some()
    {
        return Chain::Container { container: id };
    }
    Chain::Raw
}

/// Turns a path and/or a probed prefix into a concrete pipeline.
///
/// The extension is consulted first, against the full magic-hit set; priority
/// decides only when the path is silent or names a format whose magic did not
/// match. Failure names the bytes actually seen so a misdetection is
/// debuggable without library prints.
pub fn resolve_chain(reg: &Registry, path: Option<&Path>, prefix: &[u8]) -> Result<Chain> {
    let mut candidates = reg.match_magic(prefix);

    if candidates.len() > 1 {
        // The extension is consulted FIRST, and against every magic hit — a
        // path saying `.apk` must reach apk even though zip outranks it. That
        // is the spec's own worked example, and ranking cannot be allowed to
        // pre-empt an explicit filename. Priority decides only when the path
        // is silent, or names a format whose magic never matched.
        let by_ext =
            path.and_then(|p| extensions(p).iter().rev().find_map(|e| reg.by_extension(e)));
        match by_ext.filter(|id| candidates.contains(id)) {
            Some(id) => candidates = vec![id],
            None => {
                let top = reg.priority_of(candidates[0]);
                let tied: Vec<FormatId> = candidates
                    .iter()
                    .copied()
                    .filter(|id| reg.priority_of(*id) == top)
                    .collect();
                if tied.len() == 1 {
                    candidates = tied;
                } else {
                    let names: Vec<&str> = tied.iter().map(|id| id.as_str()).collect();
                    return Err(Error::AmbiguousFormat {
                        candidates: names.join(", "),
                    });
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

/// Builds `innermost` back up under each codec in `layers`, outermost last so
/// the final fold produces the correct nesting order.
fn wrap_layers(layers: &[FormatId], innermost: Chain) -> Chain {
    layers
        .iter()
        .rev()
        .fold(innermost, |inner, codec| Chain::Codec {
            codec: *codec,
            inner: Box::new(inner),
        })
}

/// Decodes `src` through every [`Chain::Codec`] layer named in `chain`,
/// outermost first, so the returned source is positioned exactly where
/// `chain`'s innermost entry (a [`Chain::Container`] or [`Chain::Raw`])
/// begins. A chain with no codec layers at all (a bare container) hands
/// `src` back untouched.
fn decode_through_chain(
    reg: &Registry,
    chain: &Chain,
    src: Box<dyn Source>,
    opts: &DecodeOpts,
) -> Result<Box<dyn Source>> {
    match chain {
        Chain::Codec { codec, inner } => {
            let decoded = reg.require_codec(*codec)?.decoder(src, opts)?;
            decode_through_chain(reg, inner, decoded, opts)
        }
        Chain::Container { .. } | Chain::Raw => Ok(src),
    }
}

/// [`resolve_chain`], but when the outer layer is a codec whose inner the
/// path left as [`Chain::Raw`] — whether because there was no path at all,
/// or because the path's own extensions ran out before naming a container —
/// keeps going: decodes that layer, peeks [`PROBE_LEN`] of the *decoded*
/// bytes, and resolves again from the decoded bytes' own magic. Closes the
/// Phase 0 limitation where a codec on stdin always bottomed out at Raw
/// purely for lack of an extension.
///
/// The path still gets first say: `resolve_chain` runs once with it, and if
/// that alone already resolves the full chain (a bare container, or a codec
/// whose inner the extensions named directly — `.tar.gz`), peeking never
/// happens. Peeking is what runs when the path is silent, or was not enough.
///
/// Bounded by [`MAX_CHAIN_DEPTH`] on **both** routes, because re-probing a
/// *decoded* stream is exactly what makes unbounded nesting attackable: each
/// layer is cheap to produce and expensive to expand. A path is a name, not
/// a proof — `a.gz.gz.gz.gz.gz` is refused the same way piped bytes with the
/// identical shape are, and exceeding the bound is a typed
/// [`Error::ChainTooDeep`], never a panic and never a silent stop.
///
/// Returns the resolved [`Chain`] alongside a [`Source`] **already decoded
/// through every codec layer named in that `Chain`** — positioned exactly
/// where the chain's innermost entry begins, ready to hand straight to a
/// container or to read as raw bytes. This holds on both routes: a path
/// that resolves in one step (no peeking needed) still gets its codec
/// layers decoded before the source comes back, so a caller never has to
/// ask whether the source it received happens to be raw or already decoded.
pub fn resolve_chain_deep(
    reg: &Registry,
    path: Option<&Path>,
    src: Box<dyn Source>,
) -> Result<(Chain, Box<dyn Source>)> {
    resolve_chain_deep_with(reg, path, src, &DecodeOpts::default())
}

/// [`resolve_chain_deep`], but with the [`DecodeOpts`] every codec layer's
/// decoder is built from spelled out by the caller instead of defaulted.
///
/// This exists because [`DecodeOpts::memory_limit`] is the ONLY guard that
/// can see a pure codec's pre-output dictionary allocation — the one sized
/// from a value the file declares in its own header, before a single decoded
/// byte exists. `--max-ratio` counts decoded output bytes and so cannot see
/// it at all. Resolving a chain builds a decoder per codec layer, so a
/// resolver that defaults its opts leaves every entry-aware verb (`list`,
/// `test`, `cat`, `unpack -C`) unbounded against a crafted `.tar.lz` whose
/// header declares a 512 MiB dictionary, while the single-stream path
/// refuses the same bytes at exit 6.
///
/// `resolve_chain_deep` remains as the "library default" spelling —
/// unbounded, matching `DecodeOpts::default()` everywhere else — but no CLI
/// path should use it: the CLI always has a resolved limit to pass.
pub fn resolve_chain_deep_with(
    reg: &Registry,
    path: Option<&Path>,
    src: Box<dyn Source>,
    opts: &DecodeOpts,
) -> Result<(Chain, Box<dyn Source>)> {
    let (prefix, src) = probe(src)?;
    let chain = resolve_chain(reg, path, &prefix)?;

    // Either a bare container, or a codec whose inner the path already named
    // (e.g. `.tar.gz`) — the path (if any) is done contributing. Decode
    // through whatever codec layers `chain` names and stop; there is nothing
    // left to peek.
    if !matches!(&chain, Chain::Codec { inner, .. } if matches!(inner.as_ref(), Chain::Raw)) {
        let decoded = decode_through_chain(reg, &chain, src, opts)?;
        return Ok((chain, decoded));
    }

    // The chain bottoms out at Raw. From here, only the decoded bytes' own
    // magic decides — the path, if there was one, already had its say above
    // and found nothing further.
    let Chain::Codec { codec, .. } = chain else {
        unreachable!("guarded above: chain is Chain::Codec with a Raw inner")
    };
    let mut layers: Vec<FormatId> = vec![codec];
    let mut current_codec = codec;
    let mut src = src;
    let mut depth = 1usize;

    loop {
        if depth >= MAX_CHAIN_DEPTH {
            return Err(Error::ChainTooDeep {
                depth: MAX_CHAIN_DEPTH,
            });
        }

        let decoded = reg.require_codec(current_codec)?.decoder(src, opts)?;
        let (next_prefix, next_src) = probe(decoded)?;
        depth += 1;

        let next_chain = match resolve_chain(reg, None, &next_prefix) {
            Ok(chain) => chain,
            Err(Error::UnknownFormat { .. }) => {
                return Ok((wrap_layers(&layers, Chain::Raw), next_src));
            }
            Err(e) => return Err(e),
        };

        let Chain::Codec { codec: nested, .. } = next_chain else {
            return Ok((wrap_layers(&layers, next_chain), next_src));
        };

        layers.push(nested);
        current_codec = nested;
        src = next_src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{Codec, DecodeOpts, EncodeOpts, Sink};
    use crate::format::{CodecCaps, FormatId, FormatMeta, MagicRule};
    use crate::registry::Registry;
    use crate::source::{ReaderSource, Source, StreamOnly};
    use crate::testing::{
        MOCK_CODEC, MOCK_CONTAINER, MockCodec, MockContainer, SharedBuf, mock_archive_bytes,
    };
    use std::io;
    use std::io::{Read, Write};
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
            FormatMeta::codec(GZIP, &["gz", "tgz"], GZIP_MAGIC),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(TAR, &["tar"], TAR_MAGIC),
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

    /// `Chain::container` must see THROUGH codec layers, not only name a
    /// bare container. `ops::inspect` uses it to decide whether it may report
    /// a fidelity conclusion, and `backup.tar.gz` has a container it has not
    /// opened just as surely as `backup.tar` does — a non-recursive version
    /// would quietly re-introduce the false negative for every `.tar.gz`.
    #[test]
    fn chain_container_sees_through_codec_layers() {
        let tar = FormatId::new("tar");
        assert_eq!(Chain::Container { container: tar }.container(), Some(tar));
        assert_eq!(
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Container { container: tar }),
            }
            .container(),
            Some(tar),
            "tar over gzip still has a container nobody has opened"
        );
        assert_eq!(
            Chain::Codec {
                codec: GZIP,
                inner: Box::new(Chain::Raw),
            }
            .container(),
            None,
            "a bare codec stream has no container, so an empty warning list is a real finding"
        );
        assert_eq!(Chain::Raw.container(), None);
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
    fn a_compound_extension_resolves_without_a_registered_compound_alias() {
        // `.tgz` means "t" + gzip's own extension. Resolving it must not depend
        // on gzip having separately registered "tgz" itself: a codec that
        // forgets that alias would otherwise silently yield Raw instead of
        // tar-over-<codec>, with no error raised.
        let mut r = Registry::new();
        r.register_codec(
            Arc::new(MockCodec),
            FormatMeta::codec(GZIP, &["gz"], GZIP_MAGIC), // deliberately NO "tgz" alias
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(TAR, &["tar"], TAR_MAGIC),
        );

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
    fn probe_does_not_consume_a_seekable_stream_either() {
        // Non-consumption has two implementations — rewind for a seekable
        // source, replay for a pipe. Only the pipe path was covered.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, b"HEADERbody").unwrap();
        let (_, path) = f.keep().unwrap();
        let src: Box<dyn Source> = Box::new(crate::source::FileSource::open(&path).unwrap());

        let (prefix, mut rest) = probe(src).unwrap();
        assert_eq!(&prefix[..6], b"HEADER");

        let mut all = Vec::new();
        rest.read_to_end(&mut all).unwrap();
        assert_eq!(
            all, b"HEADERbody",
            "a seekable source must be rewound to byte zero"
        );
    }

    #[test]
    fn probe_bounds_the_window_on_a_seekable_stream_too() {
        let big = vec![b'x'; PROBE_LEN * 3];
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &big).unwrap();
        let (_, path) = f.keep().unwrap();
        let src: Box<dyn Source> = Box::new(crate::source::FileSource::open(&path).unwrap());

        let (prefix, _) = probe(src).unwrap();
        assert_eq!(prefix.len(), PROBE_LEN);
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

    #[test]
    fn equally_ranked_candidates_with_no_extension_are_an_error_not_a_guess() {
        // A piped stream has no path to disambiguate with. Guessing silently is
        // how a zip becomes an apk.
        const A: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("alpha"),
        }];
        const B: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("beta"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("alpha"), &["alpha"], A),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("beta"), &["beta"], B),
        );

        let err = resolve_chain(&r, None, b"PKrest").unwrap_err();
        assert!(matches!(err, crate::Error::AmbiguousFormat { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("alpha") && msg.contains("beta"),
            "must name the candidates: {msg}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn a_higher_priority_candidate_resolves_without_an_extension() {
        const A: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("alpha"),
        }];
        const B: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("beta"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("alpha"), &["alpha"], A).with_priority(-5),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("beta"), &["beta"], B),
        );

        let chain = resolve_chain(&r, None, b"PKrest").unwrap();
        assert_eq!(
            chain,
            Chain::Container {
                container: FormatId::new("beta")
            }
        );
    }

    #[test]
    fn an_extension_still_disambiguates_equal_candidates() {
        const A: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("alpha"),
        }];
        const B: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("beta"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("alpha"), &["alpha"], A),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("beta"), &["beta"], B),
        );

        let chain = resolve_chain(&r, Some(Path::new("x.beta")), b"PKrest").unwrap();
        assert_eq!(
            chain,
            Chain::Container {
                container: FormatId::new("beta")
            }
        );
    }

    #[test]
    fn an_extension_outside_the_tied_set_does_not_break_the_tie() {
        // A tie between two formats sharing a magic, with a path whose
        // extension names a THIRD format that does not share it. The extension
        // must not select a format whose magic never matched, and the error
        // must name the genuinely tied candidates rather than the irrelevant
        // one.
        const A: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("alpha"),
        }];
        const B: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("beta"),
        }];
        const C: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"GZ",
            format: FormatId::new("gamma"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("alpha"), &["alpha"], A),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("beta"), &["beta"], B),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("gamma"), &["gamma"], C),
        );

        let err = resolve_chain(&r, Some(Path::new("x.gamma")), b"PKrest").unwrap_err();
        assert!(matches!(err, crate::Error::AmbiguousFormat { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("alpha") && msg.contains("beta"),
            "must name the tied candidates: {msg}"
        );
        assert!(
            !msg.contains("gamma"),
            "must not name the irrelevant extension: {msg}"
        );
    }

    #[test]
    fn an_extension_reaches_a_lower_priority_format_that_shares_the_magic() {
        // The spec's worked example: zip outranks apk on a bare stream, but a
        // path saying `.apk` must still reach apk. Ranking must not override an
        // explicit filename.
        const ZIP_MAGIC: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("zip"),
        }];
        const APK_MAGIC: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK",
            format: FormatId::new("apk"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("zip"), &["zip"], ZIP_MAGIC),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("apk"), &["apk"], APK_MAGIC).with_priority(-5),
        );

        // With no path, the higher-priority zip wins on the bare magic hit.
        let chain = resolve_chain(&r, None, b"PKrest").unwrap();
        assert_eq!(
            chain,
            Chain::Container {
                container: FormatId::new("zip")
            }
        );

        // Same bytes, but the path names apk — the lower-ranked candidate must
        // still be reached; ranking cannot pre-empt an explicit filename.
        let chain = resolve_chain(&r, Some(Path::new("archive.apk")), b"PKrest").unwrap();
        assert_eq!(
            chain,
            Chain::Container {
                container: FormatId::new("apk")
            }
        );
    }

    /// A `Source` that lies: it claims `seekable: true` but `as_seek()`
    /// always returns `None`. Nothing in this crate can implement `Source`
    /// this way today, but the trait is public and a third-party codec could
    /// — the point of this test is that `probe` must survive that instead of
    /// panicking.
    struct LiesAboutSeekability(std::io::Cursor<Vec<u8>>);

    impl Read for LiesAboutSeekability {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, buf)
        }
    }

    impl Source for LiesAboutSeekability {
        fn caps(&self) -> crate::source::SourceCaps {
            crate::source::SourceCaps {
                seekable: true,
                len: Some(self.0.get_ref().len() as u64),
            }
        }

        fn as_seek(&mut self) -> Option<&mut dyn crate::source::SeekRead> {
            None
        }
    }

    #[test]
    fn a_source_that_claims_seekable_but_has_no_seek_view_errors_instead_of_panicking() {
        let src: Box<dyn Source> = Box::new(LiesAboutSeekability(std::io::Cursor::new(
            b"payload".to_vec(),
        )));
        // Not `.unwrap_err()`: the `Ok` side is `(Vec<u8>, Box<dyn Source>)`,
        // and `Source` is not `Debug`, so `Result::unwrap_err`'s `T: Debug`
        // bound can't be satisfied here.
        match probe(src) {
            Err(err) => assert!(
                matches!(err, crate::Error::NotSeekable { .. }),
                "must be NotSeekable, not a panic: {err:?}"
            ),
            Ok(_) => panic!("expected NotSeekable, got Ok"),
        }
    }

    // --- Peek-based inner resolution (Task 4) -----------------------------
    //
    // `testing::MockCodec`'s bitwise-NOT transform is its own inverse:
    // encoding through it an EVEN number of times reproduces the original
    // bytes exactly, which would make a nesting-depth test silently
    // degenerate (the "6-deep" stream would collapse back to the bare
    // container and never exercise the bound at all). `PrefixedMockCodec`
    // instead prepends a fixed magic and passes the payload through
    // unchanged, so decoding always strips exactly one layer no matter how
    // many are stacked.
    const NESTED_MAGIC: &[u8] = b"MOCK";

    struct PrefixedMockCodec;

    impl Codec for PrefixedMockCodec {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }

        fn caps(&self) -> CodecCaps {
            CodecCaps {
                encode: true,
                decode: true,
                ..Default::default()
            }
        }

        fn decoder(&self, mut src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
            let mut discard = vec![0u8; NESTED_MAGIC.len()];
            src.read_exact(&mut discard)?;
            Ok(Box::new(StreamOnly::new(src)))
        }

        fn encoder(
            &self,
            mut dst: Box<dyn Write + Send>,
            _o: &EncodeOpts,
        ) -> Result<Box<dyn Sink>> {
            dst.write_all(NESTED_MAGIC)?;
            Ok(Box::new(PassthroughSink(dst)))
        }
    }

    struct PassthroughSink(Box<dyn Write + Send>);

    impl Write for PassthroughSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl Sink for PassthroughSink {
        fn finish(mut self: Box<Self>) -> Result<()> {
            self.0.flush()?;
            Ok(())
        }
    }

    fn mock_registry_with_codec_and_container() -> Registry {
        const CODEC_MAGIC: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: NESTED_MAGIC,
            format: MOCK_CODEC,
        }];
        const CONTAINER_MAGIC: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"ME",
            format: MOCK_CONTAINER,
        }];
        let mut r = Registry::new();
        r.register_codec(
            Arc::new(PrefixedMockCodec),
            FormatMeta::codec(MOCK_CODEC, &["mock"], CODEC_MAGIC),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(MOCK_CONTAINER, &["mar"], CONTAINER_MAGIC),
        );
        r
    }

    /// Wraps `payload` in one `PrefixedMockCodec` layer, via the codec's own
    /// `encoder` rather than hand-building the bytes, so the fixture is
    /// provably decodable by the exact codec `resolve_chain_deep` will call.
    fn mock_codec_encode(payload: &[u8]) -> Vec<u8> {
        let sink = SharedBuf::new();
        let mut s = PrefixedMockCodec
            .encoder(Box::new(sink.clone()), &EncodeOpts::default())
            .unwrap();
        s.write_all(payload).unwrap();
        s.finish().unwrap();
        sink.contents()
    }

    #[test]
    fn a_container_inside_a_codec_resolves_from_the_stream_with_no_path() {
        let reg = mock_registry_with_codec_and_container();
        let inner = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let outer = mock_codec_encode(&inner);

        let (chain, _src) = resolve_chain_deep(
            &reg,
            None,
            Box::new(ReaderSource::new(io::Cursor::new(outer))),
        )
        .expect("resolve");

        // Before this task the inner layer was Chain::Raw, because no path meant
        // no extension to consult. The prefix of the DECODED stream now decides.
        assert_eq!(
            chain,
            Chain::Codec {
                codec: MOCK_CODEC,
                inner: Box::new(Chain::Container {
                    container: MOCK_CONTAINER
                }),
            },
            "a container nested inside a codec must be found by peeking the decoded stream"
        );
    }

    #[test]
    fn nesting_beyond_the_depth_bound_is_a_typed_error_naming_the_depth() {
        let reg = mock_registry_with_codec_and_container();
        let mut bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        for _ in 0..MAX_CHAIN_DEPTH + 2 {
            bytes = mock_codec_encode(&bytes);
        }

        // Not `.expect_err(..)`: the `Ok` side is `(Chain, Box<dyn Source>)`,
        // and `Source` is not `Debug`, so `Result::expect_err`'s `T: Debug`
        // bound can't be satisfied here — same reason as
        // `a_source_that_claims_seekable_but_has_no_seek_view_errors_instead_of_panicking`
        // above.
        match resolve_chain_deep(
            &reg,
            None,
            Box::new(ReaderSource::new(io::Cursor::new(bytes))),
        ) {
            Err(Error::ChainTooDeep { depth }) => assert_eq!(depth, MAX_CHAIN_DEPTH),
            Err(other) => panic!("expected ChainTooDeep, got {other:?}"),
            Ok(_) => panic!("nesting past the bound must be refused"),
        }
    }

    #[test]
    fn nesting_beyond_the_depth_bound_is_refused_via_the_path_route_too() {
        // A path is a name, not a proof: `a.gz.gz.gz.gz.gz` must be refused
        // exactly like the identical bytes arriving with no path at all.
        // `mock_registry_with_codec_and_container` only ever exposes a
        // single extension per format ("mock"), so a path naming it gives
        // `inner_from_path` nothing to find a container with — the chain
        // still bottoms out at Raw, and peeking (and the bound) must engage
        // all the same.
        let reg = mock_registry_with_codec_and_container();
        let mut bytes = mock_archive_bytes(&[("a.txt", b"alpha")]);
        for _ in 0..MAX_CHAIN_DEPTH + 2 {
            bytes = mock_codec_encode(&bytes);
        }

        match resolve_chain_deep(
            &reg,
            Some(Path::new("nested.mock")),
            Box::new(ReaderSource::new(io::Cursor::new(bytes))),
        ) {
            Err(Error::ChainTooDeep { depth }) => assert_eq!(depth, MAX_CHAIN_DEPTH),
            Err(other) => panic!("expected ChainTooDeep, got {other:?}"),
            Ok(_) => panic!("nesting past the bound must be refused, path or no path"),
        }
    }

    #[test]
    fn the_returned_source_is_decoded_through_every_codec_layer_on_both_routes() {
        // The defect this pins: the path route used to return the PRISTINE,
        // undecoded source (resolve_chain alone tells you the shape, nothing
        // decodes anything), while the no-path route returned the source
        // already peeled past every codec layer. A caller of
        // `resolve_chain_deep` cannot be expected to inspect `path.is_some()`
        // itself to know which kind of source it was just handed — both
        // routes must leave the source in the identical state: decoded
        // through every codec layer named in the returned `Chain`, ready to
        // hand straight to the container.
        //
        // "thing.mar.mock" mirrors `.tar.gz`: `inner_from_path` finds the
        // container ("mar") one extension in from the codec ("mock"), so
        // this path resolves the FULL chain in one `resolve_chain` call,
        // with no peeking at all — the route this test must prove decodes
        // its codec layer exactly as the peeling route does.
        let reg = mock_registry_with_codec_and_container();
        let inner = mock_archive_bytes(&[("a.txt", b"alpha")]);
        let outer = mock_codec_encode(&inner);

        let (chain_with_path, mut src_with_path) = resolve_chain_deep(
            &reg,
            Some(Path::new("thing.mar.mock")),
            Box::new(ReaderSource::new(io::Cursor::new(outer.clone()))),
        )
        .expect("resolve with path");
        let (chain_no_path, mut src_no_path) = resolve_chain_deep(
            &reg,
            None,
            Box::new(ReaderSource::new(io::Cursor::new(outer))),
        )
        .expect("resolve without path");

        let expected_chain = Chain::Codec {
            codec: MOCK_CODEC,
            inner: Box::new(Chain::Container {
                container: MOCK_CONTAINER,
            }),
        };
        assert_eq!(chain_with_path, expected_chain);
        assert_eq!(chain_no_path, expected_chain);

        let mut bytes_with_path = Vec::new();
        src_with_path.read_to_end(&mut bytes_with_path).unwrap();
        let mut bytes_no_path = Vec::new();
        src_no_path.read_to_end(&mut bytes_no_path).unwrap();

        assert_eq!(
            bytes_with_path, inner,
            "the path route must decode through the codec layer, not return raw bytes"
        );
        assert_eq!(
            bytes_with_path, bytes_no_path,
            "both routes must leave the source in the identical, already-decoded state"
        );
    }
}
