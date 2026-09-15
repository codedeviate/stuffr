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
#[cfg(feature = "arj")]
pub mod arj;
// The least-significant-bit-first bit reader ARC's two bitstreams and ZOO's
// `lzd` all read through. See its own module doc for why THIS is shared
// where the LZW engines built on it are deliberately not.
#[cfg(any(feature = "arc", feature = "zoo"))]
mod bits;
#[cfg(feature = "compress")]
pub mod compress_z;
#[cfg(any(feature = "lha", feature = "arc", feature = "zoo"))]
mod crc;
// The DOS packed-timestamp helper every date-carrying legacy container uses.
// `lha` joined this list in Phase 3c Task 6: its encoder is the first
// thing here that has to WRITE a DOS timestamp rather than only parse one.
#[cfg(any(feature = "arj", feature = "arc", feature = "zoo", feature = "lha"))]
mod dos;
#[cfg(feature = "lha")]
pub mod lha;
#[cfg(feature = "zoo")]
pub mod zoo;
