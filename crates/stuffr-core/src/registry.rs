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
        let mut hits: Vec<FormatId> = self
            .magics
            .iter()
            .filter(|m| {
                let end = m.offset + m.bytes.len();
                prefix.len() >= end && &prefix[m.offset..end] == m.bytes
            })
            .map(|m| m.format)
            .collect();
        hits.sort_by_key(|id| id.as_str());
        hits.dedup();
        hits
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
    use crate::testing::{MOCK_CODEC, MOCK_CONTAINER, MockCodec, MockContainer};

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
        FormatMeta {
            id: MOCK_CODEC,
            kind: FormatKind::Codec,
            extensions: &["mk", "mock"],
            magics: CODEC_MAGIC,
        }
    }

    fn container_meta() -> FormatMeta {
        FormatMeta {
            id: MOCK_CONTAINER,
            kind: FormatKind::Container,
            extensions: &["mar"],
            magics: CONTAINER_MAGIC,
        }
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
            FormatMeta {
                id: FormatId::new("tar"),
                kind: FormatKind::Container,
                extensions: &["tar"],
                magics: OFFSET_MAGIC,
            },
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
            FormatMeta {
                id: MOCK_CODEC,
                kind: FormatKind::Codec,
                extensions: &["mk2"],
                magics: CODEC_MAGIC,
            },
        );
        assert_eq!(r.by_extension("mk2"), Some(MOCK_CODEC));
        assert_eq!(
            r.by_extension("mk"),
            None,
            "a stale extension must not survive re-registration"
        );
        assert_eq!(r.by_extension("mock"), None);
    }
}
