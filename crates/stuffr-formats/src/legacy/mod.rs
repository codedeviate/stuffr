//! Legacy formats: ARC/PAK, ZOO, LHA/LZH, ARJ and Unix `compress`.
//!
//! **Three of the five write now** — `compress` (Phase 3c Task 5), `lha`
//! (Task 6) and `arj` (Task 7) — so "read-only" is no longer what groups
//! them; `arc` and `zoo` alone still refuse `pack --format <name>` at exit
//! 3. What they DO still share, and what the rest of `stuffr-formats` does
//! not, is where their expectations come from: each is proven against a
//! fixture whose expected output is known by construction or borrowed with
//! its provenance written down, rather than produced by this project's own
//! encoder. That distinction OUTLIVED the encoders and is the reason not
//! one of the five fixtures was regenerated when its format gained one —
//! an input produced by the code under test is no input at all. See
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md` for how each fixture
//! was made, and for which of them an implementation outside this project
//! has ever agreed with (`hello.Z`: yes, by construction; `sample.lzh`:
//! yes, `lhasa`; the ARC/ZOO corpus: yes, borrowed whole; `sample.arj`:
//! **no**, and `legacy::arj`'s module doc opens with what follows from
//! that).

#[cfg(feature = "arc")]
pub mod arc;
// Salvage Stage 2 Task 3: scans an ARC archive for entry headers directly,
// the way `../zip_salvage.rs` does for zip, rather than trusting a single
// linear pass that stops at the first damaged record. Reuses `arc.rs`'s own
// `ArcHeader::parse`, `Method` and `decode` — see that module's doc for why
// several of its items are `pub(super)` rather than private.
#[cfg(feature = "arc")]
pub mod arc_salvage;
#[cfg(feature = "arj")]
pub mod arj;
// Salvage Stage 2 Task 6: scans an ARJ archive for local file headers
// directly, rather than walking forward from the main header the way
// `unarj_rs::ArjArchieve` does — one damaged header ends that walk and every
// entry behind it with it. Owns its own header parser for the reason
// `lha_salvage.rs` does: `arj.rs` delegates every read to `unarj-rs`, whose
// `LocalFileHeader::load_from` indexes unconditionally and cannot be pointed
// at hostile bytes, and whose basic-header CRC-32 is the gate this crate has
// to be able to falsify.
#[cfg(feature = "arj")]
pub mod arj_salvage;
// The least-significant-bit-first bit reader ARC's two bitstreams and ZOO's
// `lzd` all read through. See its own module doc for why THIS is shared
// where the LZW engines built on it are deliberately not.
#[cfg(any(feature = "arc", feature = "zoo"))]
mod bits;
#[cfg(feature = "compress")]
pub mod compress_z;
// `zip` joined this gate in Salvage Stage 2 Task 1: `../salvage_verify.rs`'s
// shared verifier resumes `crc16_arc_continued` from its `Verifier::Crc16`
// arm regardless of which OTHER legacy format is enabled, since that match
// is on a runtime value, not a feature — so this module must be reachable
// whenever `zip` alone is, not only alongside `lha`/`arc`/`zoo`.
// `pub(crate)`, not private: `../salvage_verify.rs` — a sibling of `legacy`,
// not a descendant of it — is the second caller this task adds.
// `arj` joined in Task 6, for the same reason `zip` did: its salvage scanner
// goes through `../salvage_verify.rs`, whose `Verifier::Crc16` arm reaches
// `crc16_arc_continued` on a RUNTIME match rather than a feature one — so
// this module must compile whenever that one does, even though no ARJ header
// carries a CRC-16 of its own.
#[cfg(any(
    feature = "lha",
    feature = "arc",
    feature = "zoo",
    feature = "zip",
    feature = "arj"
))]
pub(crate) mod crc;
// The DOS packed-timestamp helper every date-carrying legacy container uses.
// `lha` joined this list in Phase 3c Task 6: its encoder is the first
// thing here that has to WRITE a DOS timestamp rather than only parse one.
#[cfg(any(feature = "arj", feature = "arc", feature = "zoo", feature = "lha"))]
mod dos;
#[cfg(feature = "lha")]
pub mod lha;
// Salvage Stage 2 Task 5: scans an LHA/LZH archive for entry headers
// directly, rather than following the chain of `skip size` hops `lha.rs`'s
// reader walks from the front of the file — LHA has no index, no entry count
// and no trailer, so one damaged header ends the archive for any ordinary
// reader and every entry behind it with it. Unlike its ARC and ZOO siblings
// this one owns its own header parser: `lha.rs` delegates every read to
// `delharc`, and the level-0/1 HEADER CHECKSUM has to be a gate criterion
// this crate can falsify. See that module's doc for where each byte offset
// comes from, and for the cross-check that pins the parser against
// `delharc`'s own.
#[cfg(feature = "lha")]
pub mod lha_salvage;
#[cfg(feature = "zoo")]
pub mod zoo;
// Salvage Stage 2 Task 4: scans a ZOO archive for directory records
// directly, rather than following the linked list of absolute file offsets
// `zoo.rs`'s own reader walks — when the chain itself is the damage, that
// walk is what cannot be trusted. Reuses `zoo.rs`'s own `read_dir_entry`,
// `DirEntry`, `Method` and `decode` rather than carrying a second copy of
// the 56-byte record layout, which is the exact figure `unarc-rs` gets
// wrong; see that module's doc for why several of its items are
// `pub(super)`.
#[cfg(feature = "zoo")]
pub mod zoo_salvage;
