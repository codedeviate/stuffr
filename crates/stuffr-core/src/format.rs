use std::fmt;

/// A stable, human-readable format identifier. `&'static str` rather than an
/// enum so `stuffr-formats` can add formats without editing this crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FormatId(&'static str);

impl FormatId {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatKind {
    /// A byte-stream transform. Knows nothing about files or entries.
    Codec,
    /// A structure of entries. May invoke codecs internally.
    Container,
}

/// What a codec can do. Every field defaults to `false`: a backend must opt in.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CodecCaps {
    pub encode: bool,
    pub decode: bool,
    pub parallel_encode: bool,
    pub parallel_decode: bool,
    /// Stream carries a frame/block index enabling random access.
    pub frame_index: bool,
}

/// What a container can do, and what it needs from its input.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ContainerCaps {
    pub read: bool,
    pub write: bool,
    /// Entries can be enumerated from a forward-only source at full data
    /// fidelity (metadata may be approximate). True for zip, tar, cpio.
    pub forward_parse: bool,
    /// Only a best-effort salvage scan is possible forward-only. Distinct from
    /// `forward_parse`: this rung yields partial results by construction.
    pub degraded_parse: bool,
    /// The authoritative index lives at the end of the stream (zip, 7z, rar).
    pub trailing_index: bool,
    /// Entries share codec state, so reaching entry N decodes 1..N (7z, rar).
    pub solid: bool,
    /// Each entry carries its own codec (zip, 7z).
    pub per_entry_codec: bool,
    /// Random access is required even to enumerate (squashfs, iso).
    pub needs_seek: bool,
}

/// A magic-byte rule. Detection matches these against a bounded prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MagicRule {
    pub offset: usize,
    pub bytes: &'static [u8],
    pub format: FormatId,
}

/// Registration metadata for one format.
#[derive(Clone, Copy, Debug)]
pub struct FormatMeta {
    pub id: FormatId,
    pub kind: FormatKind,
    /// Extensions without the leading dot, lowercase. e.g. `["gz", "tgz"]`.
    pub extensions: &'static [&'static str],
    pub magics: &'static [MagicRule],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_id_round_trips_and_displays() {
        let id = FormatId::new("gzip");
        assert_eq!(id.as_str(), "gzip");
        assert_eq!(id.to_string(), "gzip");
    }

    #[test]
    fn caps_default_to_no_capability() {
        // A format must opt in to every capability. Defaulting to `true`
        // anywhere would let an unimplemented backend silently claim support.
        let c = CodecCaps::default();
        assert!(!c.encode && !c.decode && !c.parallel_encode);
        let k = ContainerCaps::default();
        assert!(!k.read && !k.write && !k.forward_parse && !k.needs_seek);
    }
}
