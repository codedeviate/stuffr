use std::fmt;

/// A stable, human-readable format identifier. `&'static str` rather than an
/// enum so `stuffr-formats` can add formats without editing this crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
    /// The format carries an integrity check — CRC, checksum, or framing —
    /// that makes malformed input detectable.
    ///
    /// `false` for raw streams: a bare deflate or LZMA1 stream fed corrupt
    /// bytes produces different output rather than an error. Such a format can
    /// never produce [`crate::Error::Corrupt`], and a caller is entitled to
    /// know that rather than assume a guarantee that is not there.
    pub detects_corruption: bool,

    /// Rough working-set cost of one encode worker, in bytes, when the codec
    /// knows it. `None` means unknown — assume modest.
    ///
    /// Unused until Phase 1e wires parallel encode; it exists now because the
    /// governor already reasons about figures like "xz -9 at ~700 MiB per
    /// worker" with no way for a codec to supply one, and adding the field
    /// after nine codecs exist means revisiting all nine.
    pub memory_per_worker: Option<u64>,

    /// This build's encoder for the format is markedly worse than the format's
    /// usual one — a fallback that produces valid output nobody would choose.
    ///
    /// `ops` refuses to use it unless the caller opts in, because the output is
    /// indistinguishable afterwards: a user who asked for `.xz` expects xz
    /// ratios, and two builds of stf would otherwise produce very different
    /// files from an identical command with no way to tell which they got.
    pub weak_encoder: bool,
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
    /// Breaks ties when several formats share a magic. Higher wins.
    ///
    /// The ZIP family is why this exists: jar, apk, docx, epub, odt and zip all
    /// begin `PK\x03\x04`, so longest-magic-wins cannot separate them. Rank the
    /// base format above its derivatives, and a bare stream resolves to the
    /// base while a derivative is reached by extension.
    pub priority: i16,
}

impl CodecCaps {
    /// A codec that both compresses and decompresses, with no parallelism and
    /// no frame index. The common shape.
    pub const fn round_trip() -> Self {
        Self {
            encode: true,
            decode: true,
            parallel_encode: false,
            parallel_decode: false,
            frame_index: false,
            detects_corruption: false,
            memory_per_worker: None,
            weak_encoder: false,
        }
    }

    /// A decode-only codec — the pure-Rust fallbacks that let a build with no C
    /// toolchain still *open* a `.zst` or `.xz`.
    pub const fn decode_only() -> Self {
        Self {
            encode: false,
            decode: true,
            parallel_encode: false,
            parallel_decode: false,
            frame_index: false,
            detects_corruption: false,
            memory_per_worker: None,
            weak_encoder: false,
        }
    }
}

impl ContainerCaps {
    /// A container that can be read but not written — RAR, whose compressor is
    /// proprietary.
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            forward_parse: false,
            degraded_parse: false,
            trailing_index: false,
            solid: false,
            per_entry_codec: false,
            needs_seek: false,
        }
    }

    /// A container supporting both directions. Every other capability stays
    /// false — a constructor must not claim what a format has not.
    pub const fn read_write() -> Self {
        let mut c = Self::read_only();
        c.write = true;
        c
    }
}

impl FormatMeta {
    pub const fn codec(
        id: FormatId,
        extensions: &'static [&'static str],
        magics: &'static [MagicRule],
    ) -> Self {
        Self {
            id,
            kind: FormatKind::Codec,
            extensions,
            magics,
            priority: 0,
        }
    }

    pub const fn container(
        id: FormatId,
        extensions: &'static [&'static str],
        magics: &'static [MagicRule],
    ) -> Self {
        Self {
            id,
            kind: FormatKind::Container,
            extensions,
            magics,
            priority: 0,
        }
    }

    pub const fn with_priority(mut self, priority: i16) -> Self {
        self.priority = priority;
        self
    }
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

    #[test]
    fn codec_caps_constructors_express_the_two_common_shapes() {
        let rt = CodecCaps::round_trip();
        assert!(rt.encode && rt.decode);
        assert!(!rt.parallel_encode && !rt.parallel_decode && !rt.frame_index);

        // The pure ruzstd / lzma-rs fallbacks: openable, not writable.
        let d = CodecCaps::decode_only();
        assert!(d.decode && !d.encode);
    }

    #[test]
    fn container_caps_constructors_express_the_two_common_shapes() {
        let ro = ContainerCaps::read_only();
        assert!(ro.read && !ro.write);
        let rw = ContainerCaps::read_write();
        assert!(rw.read && rw.write);
        // Everything else stays opt-in — a constructor must not smuggle in
        // capabilities a format has not claimed.
        assert!(!rw.forward_parse && !rw.trailing_index && !rw.needs_seek);
    }

    #[test]
    fn format_meta_constructors_set_the_kind_for_you() {
        const M: &[MagicRule] = &[];
        let c = FormatMeta::codec(FormatId::new("gzip"), &["gz"], M);
        assert_eq!(c.kind, FormatKind::Codec);
        let k = FormatMeta::container(FormatId::new("tar"), &["tar"], M);
        assert_eq!(k.kind, FormatKind::Container);
    }
}
