//! Format registry: what this build actually contains.
//!
//! Dispatch stays internal, but discovery is explicit — `stf formats` renders
//! [`Registry::matrix`], so a user can always tell a missing feature flag from
//! a broken file.

use std::collections::HashMap;
use std::sync::Arc;

use crate::archive::{Codec, Container};
use crate::error::{Error, Result};
use crate::format::{FormatId, FormatKind, FormatMeta, MagicRule};

/// One row of the capability matrix.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FormatRow {
    pub id: FormatId,
    pub kind: FormatKind,
    pub extensions: &'static [&'static str],
    pub read: bool,
    pub write: bool,
    pub parallel: bool,
}

#[derive(Default)]
pub struct Registry {
    codecs: HashMap<FormatId, Arc<dyn Codec>>,
    containers: HashMap<FormatId, Arc<dyn Container>>,
    metas: HashMap<FormatId, FormatMeta>,
    by_ext: HashMap<String, FormatId>,
    magics: Vec<MagicRule>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    fn index(&mut self, meta: FormatMeta) {
        // Symmetric with the `magics` purge below: re-registering a format with
        // a different extension list must not leave stale mappings behind.
        self.by_ext.retain(|_, v| *v != meta.id);
        for ext in meta.extensions {
            self.by_ext.insert(ext.to_ascii_lowercase(), meta.id);
        }
        // Replace rather than duplicate on re-registration.
        self.magics.retain(|m| m.format != meta.id);
        self.magics.extend_from_slice(meta.magics);
        self.metas.insert(meta.id, meta);
    }

    pub fn register_codec(&mut self, codec: Arc<dyn Codec>, meta: FormatMeta) {
        self.codecs.insert(meta.id, codec);
        self.index(meta);
    }

    pub fn register_container(&mut self, container: Arc<dyn Container>, meta: FormatMeta) {
        self.containers.insert(meta.id, container);
        self.index(meta);
    }

    pub fn codec(&self, id: FormatId) -> Option<&Arc<dyn Codec>> {
        self.codecs.get(&id)
    }

    pub fn container(&self, id: FormatId) -> Option<&Arc<dyn Container>> {
        self.containers.get(&id)
    }

    /// Like [`Self::codec`] but yields `FormatNotEnabled` (exit 3), which is how
    /// a caller distinguishes "wrong build" from "broken file".
    pub fn require_codec(&self, id: FormatId) -> Result<&Arc<dyn Codec>> {
        self.codec(id).ok_or(Error::FormatNotEnabled(id))
    }

    /// The codec for `id`, if this build has it **and** it can encode.
    ///
    /// Separate from [`Self::require_codec`] because a codec that cannot encode
    /// is a normal thing to have: the pure-Rust zstd and xz fallbacks let a
    /// build with no C toolchain still read those formats. Without this check
    /// the caller reaches `encoder()` on such a codec, and the natural body for
    /// that method is a panic — reachable straight from a command line.
    pub fn require_encoder(&self, id: FormatId) -> Result<&Arc<dyn Codec>> {
        let codec = self.require_codec(id)?;
        if !codec.caps().encode {
            return Err(Error::CapabilityUnavailable {
                format: id,
                available: "read",
                requested: "written",
            });
        }
        Ok(codec)
    }

    /// The codec for `id`, if this build has it **and** it can decode.
    pub fn require_decoder(&self, id: FormatId) -> Result<&Arc<dyn Codec>> {
        let codec = self.require_codec(id)?;
        if !codec.caps().decode {
            return Err(Error::CapabilityUnavailable {
                format: id,
                available: "written",
                requested: "read",
            });
        }
        Ok(codec)
    }

    pub fn require_container(&self, id: FormatId) -> Result<&Arc<dyn Container>> {
        self.container(id).ok_or(Error::FormatNotEnabled(id))
    }

    /// Extension lookup. Accepts `"gz"` or `".gz"`, any case.
    pub fn by_extension(&self, ext: &str) -> Option<FormatId> {
        let key = ext.trim_start_matches('.').to_ascii_lowercase();
        self.by_ext.get(&key).copied()
    }

    /// Every format whose magic matches `prefix`. Empty rather than a guess.
    pub fn match_magic(&self, prefix: &[u8]) -> Vec<FormatId> {
        let mut hits: Vec<(i16, FormatId)> = self
            .magics
            .iter()
            .filter(|m| {
                let end = match m.offset.checked_add(m.bytes.len()) {
                    Some(e) => e,
                    None => return false,
                };
                prefix.len() >= end && &prefix[m.offset..end] == m.bytes
            })
            .map(|m| {
                (
                    self.metas.get(&m.format).map_or(0, |x| x.priority),
                    m.format,
                )
            })
            .collect();
        // Priority descending, then id ascending so equal ranks stay stable.
        hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));
        hits.dedup_by_key(|(_, id)| *id);
        hits.into_iter().map(|(_, id)| id).collect()
    }

    /// The priority of a registered format, or 0 if unknown.
    pub fn priority_of(&self, id: FormatId) -> i16 {
        self.metas.get(&id).map_or(0, |m| m.priority)
    }

    /// The capability matrix, sorted by id. Rendered by `stf formats`.
    pub fn matrix(&self) -> Vec<FormatRow> {
        let mut rows: Vec<FormatRow> = self
            .metas
            .values()
            .map(|meta| {
                let (read, write, parallel) = match meta.kind {
                    FormatKind::Codec => match self.codecs.get(&meta.id) {
                        Some(c) => {
                            let caps = c.caps();
                            (
                                caps.decode,
                                caps.encode,
                                caps.parallel_encode || caps.parallel_decode,
                            )
                        }
                        None => (false, false, false),
                    },
                    FormatKind::Container => match self.containers.get(&meta.id) {
                        Some(c) => {
                            let caps = c.caps();
                            (caps.read, caps.write, false)
                        }
                        None => (false, false, false),
                    },
                };
                FormatRow {
                    id: meta.id,
                    kind: meta.kind,
                    extensions: meta.extensions,
                    read,
                    write,
                    parallel,
                }
            })
            .collect();
        rows.sort_by_key(|r| r.id.as_str());
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{DecodeOpts, EncodeOpts, Sink};
    use crate::format::CodecCaps;
    use crate::source::Source;
    use crate::testing::{MOCK_CODEC, MOCK_CONTAINER, MockCodec, MockContainer};
    use std::io::Write;

    const CODEC_MAGIC: &[MagicRule] = &[MagicRule {
        offset: 0,
        bytes: b"MOCK",
        format: MOCK_CODEC,
    }];
    const CONTAINER_MAGIC: &[MagicRule] = &[MagicRule {
        offset: 0,
        bytes: b"ME",
        format: MOCK_CONTAINER,
    }];

    fn codec_meta() -> FormatMeta {
        FormatMeta::codec(MOCK_CODEC, &["mk", "mock"], CODEC_MAGIC)
    }

    fn container_meta() -> FormatMeta {
        FormatMeta::container(MOCK_CONTAINER, &["mar"], CONTAINER_MAGIC)
    }

    fn populated() -> Registry {
        let mut r = Registry::new();
        r.register_codec(Arc::new(MockCodec), codec_meta());
        r.register_container(Arc::new(MockContainer), container_meta());
        r
    }

    #[test]
    fn an_empty_registry_reports_no_formats() {
        assert!(Registry::new().matrix().is_empty());
    }

    #[test]
    fn registered_formats_are_retrievable_by_id() {
        let r = populated();
        assert!(r.codec(MOCK_CODEC).is_some());
        assert!(r.container(MOCK_CONTAINER).is_some());
        // A codec is not a container, even under the same registry.
        assert!(r.container(MOCK_CODEC).is_none());
    }

    #[test]
    fn a_missing_format_is_format_not_enabled_not_a_generic_error() {
        // Exit code 3 is how a script distinguishes "wrong build" from "broken
        // file", so this must not collapse into a generic failure.
        //
        // Destructured with `let ... else` rather than `.unwrap_err()`:
        // `unwrap_err` would require `dyn Codec: Debug`, which would force a
        // Debug impl on every codec in the project to serve one assertion.
        let r = Registry::new();
        let Err(err) = r.require_codec(MOCK_CODEC) else {
            panic!("expected FormatNotEnabled for an unregistered codec");
        };
        assert!(matches!(err, crate::Error::FormatNotEnabled(id) if id == MOCK_CODEC));
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn extension_lookup_is_case_insensitive_and_dot_tolerant() {
        let r = populated();
        assert_eq!(r.by_extension("mk"), Some(MOCK_CODEC));
        assert_eq!(r.by_extension("MOCK"), Some(MOCK_CODEC));
        assert_eq!(r.by_extension(".mar"), Some(MOCK_CONTAINER));
        assert_eq!(r.by_extension("nope"), None);
    }

    #[test]
    fn magic_matching_finds_the_format_from_a_prefix() {
        let r = populated();
        assert_eq!(r.match_magic(b"MOCKpayload"), vec![MOCK_CODEC]);
        assert_eq!(r.match_magic(b"ME\x05\x00hello"), vec![MOCK_CONTAINER]);
    }

    #[test]
    fn magic_matching_returns_empty_rather_than_guessing() {
        let r = populated();
        assert!(r.match_magic(b"unrecognised bytes").is_empty());
        assert!(
            r.match_magic(b"").is_empty(),
            "an empty prefix matches nothing"
        );
        assert!(
            r.match_magic(b"M").is_empty(),
            "a truncated prefix must not match"
        );
    }

    #[test]
    fn magic_respects_the_declared_offset() {
        const OFFSET_MAGIC: &[MagicRule] = &[MagicRule {
            offset: 257,
            bytes: b"ustar",
            format: FormatId::new("tar"),
        }];
        let mut r = Registry::new();
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("tar"), &["tar"], OFFSET_MAGIC),
        );

        let mut buf = vec![0u8; 512];
        buf[257..262].copy_from_slice(b"ustar");
        assert_eq!(r.match_magic(&buf), vec![FormatId::new("tar")]);

        // Same bytes at the wrong offset must not match.
        let mut wrong = vec![0u8; 512];
        wrong[0..5].copy_from_slice(b"ustar");
        assert!(r.match_magic(&wrong).is_empty());
    }

    #[test]
    fn matrix_reports_capabilities_and_is_sorted() {
        let r = populated();
        let m = r.matrix();
        assert_eq!(m.len(), 2);
        assert!(m.windows(2).all(|w| w[0].id.as_str() <= w[1].id.as_str()));

        let codec_row = m.iter().find(|row| row.id == MOCK_CODEC).unwrap();
        assert_eq!(codec_row.kind, FormatKind::Codec);
        assert!(codec_row.read && codec_row.write);
        assert!(!codec_row.parallel, "the mock declares no parallelism");
        assert_eq!(codec_row.extensions, &["mk", "mock"]);
    }

    #[test]
    fn re_registering_an_id_replaces_it_rather_than_duplicating() {
        let mut r = populated();
        r.register_codec(Arc::new(MockCodec), codec_meta());
        assert_eq!(r.matrix().len(), 2);
    }

    #[test]
    fn re_registering_with_a_different_extension_list_drops_the_old_mapping() {
        let mut r = populated();
        r.register_codec(
            Arc::new(MockCodec),
            FormatMeta::codec(MOCK_CODEC, &["mk2"], CODEC_MAGIC),
        );
        assert_eq!(r.by_extension("mk2"), Some(MOCK_CODEC));
        assert_eq!(
            r.by_extension("mk"),
            None,
            "a stale extension must not survive re-registration"
        );
        assert_eq!(r.by_extension("mock"), None);
    }

    #[test]
    fn match_magic_orders_by_priority_before_id() {
        // Two formats sharing one magic — the ZIP family's exact situation.
        const SHARED: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK\x03\x04",
            format: FormatId::new("zip"),
        }];
        const SHARED2: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"PK\x03\x04",
            format: FormatId::new("apk"),
        }];

        let mut r = Registry::new();
        // "apk" sorts before "zip" alphabetically, so without priority it wins.
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("apk"), &["apk"], SHARED2).with_priority(-10),
        );
        r.register_container(
            Arc::new(MockContainer),
            FormatMeta::container(FormatId::new("zip"), &["zip"], SHARED),
        );

        let hits = r.match_magic(b"PK\x03\x04rest");
        assert_eq!(
            hits.first().copied(),
            Some(FormatId::new("zip")),
            "the base format must outrank its derivative"
        );
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn equal_priority_still_orders_deterministically_by_id() {
        const A: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"XX",
            format: FormatId::new("bbb"),
        }];
        const B: &[MagicRule] = &[MagicRule {
            offset: 0,
            bytes: b"XX",
            format: FormatId::new("aaa"),
        }];
        let mut r = Registry::new();
        r.register_codec(
            Arc::new(MockCodec),
            FormatMeta::codec(FormatId::new("bbb"), &["b"], A),
        );
        r.register_codec(
            Arc::new(MockCodec),
            FormatMeta::codec(FormatId::new("aaa"), &["a"], B),
        );
        assert_eq!(
            r.match_magic(b"XXrest"),
            vec![FormatId::new("aaa"), FormatId::new("bbb")]
        );
    }

    #[test]
    fn a_decode_only_codec_is_refused_an_encoder_rather_than_reaching_it() {
        use crate::testing::{MOCK_CODEC, MockCodec};

        /// Stands in for 1c's pure-Rust zstd and xz fallbacks: readable, not
        /// writable. Delegates decode to MockCodec so only `caps` differs.
        struct ReadOnlyCodec;
        impl Codec for ReadOnlyCodec {
            fn id(&self) -> FormatId {
                MOCK_CODEC
            }
            fn caps(&self) -> CodecCaps {
                CodecCaps::decode_only()
            }
            fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>> {
                MockCodec.decoder(src, o)
            }
            fn encoder(&self, _d: Box<dyn Write + Send>, _o: &EncodeOpts) -> Result<Box<dyn Sink>> {
                // This panic is never exercised by this test — neither the
                // test nor `require_encoder` ever calls `encoder()`. It
                // documents the production failure mode a buggy
                // implementation would hit via `ops::compress`: without the
                // capability check below, a decode-only codec's natural
                // `encoder()` body is exactly this panic, reachable straight
                // from a command line. The real assertion in this test is
                // the `Err`/exit-code check below.
                panic!("a capability check must stop the caller before it reaches here");
            }
        }

        let mut reg = Registry::new();
        reg.register_codec(
            std::sync::Arc::new(ReadOnlyCodec),
            FormatMeta::codec(MOCK_CODEC, &["mock"], &[]),
        );

        // The decoder is available.
        assert!(reg.require_decoder(MOCK_CODEC).is_ok());

        // The encoder is refused with a typed error, NOT by panicking inside
        // the codec — which is what the unreachable!/unimplemented! that a
        // codec author would naturally write there would do.
        //
        // Destructured with `let ... else` rather than `.unwrap_err()`, same
        // reason as `a_missing_format_is_format_not_enabled_not_a_generic_error`
        // above: `unwrap_err` requires the `Ok` type to be `Debug`, and the
        // `Ok` type here is `&Arc<dyn Codec>`.
        let Err(err) = reg.require_encoder(MOCK_CODEC) else {
            panic!("expected CapabilityUnavailable for a decode-only codec");
        };
        assert!(
            matches!(err, Error::CapabilityUnavailable { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("mock-codec"),
            "must name the format: {err}"
        );
        assert_eq!(
            err.exit_code(),
            3,
            "a capability refusal must be distinguishable from other errors so a script can branch on it"
        );
    }
}
