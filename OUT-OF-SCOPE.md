# Out of Scope — and the Wishlist

This file has two jobs.

**Part 1** records what `stuffr` deliberately does *not* do, so a gap reads as a
decision rather than an oversight. When something is excluded because of an
external constraint rather than our own effort budget, that is stated plainly.

**Part 2** is the wishlist: things that are genuinely wanted but not now. Nothing
here is a promise. Moving an item out of Part 2 means it gets a spec of its own.

---

# Part 1 — Out of scope

## Blocked by external constraint, not by effort

These cannot be done regardless of how much work we are willing to spend.

| Item | Constraint |
|---|---|
| **RAR compression** | The algorithm is proprietary. The freely available `unrar` source is licensed for *decompression only*. RAR is read-only, permanently. |
| **StuffIt `.sitx`, and later `.sit` methods** | Undocumented and closed. Best-effort read of the older methods; no write, ever. |
| **Any format under a live patent** | Should one surface, it is excluded until the patent lapses. |

## Excluded by choice

### Writing broken cryptography

Reading legacy encrypted archives is in scope where the format is understood.
**Creating** them is not. ZipCrypto is trivially breakable, and a tool that
happily produces it invites someone to rely on it. Read the old ones; do not make
new ones.

### GNU `tar` bug-compatibility

A `tar` compat symlink is on the wishlist, not in v1. GNU tar's flag surface is
enormous, its behaviour in corner cases is defined by its implementation rather
than a specification, and matching it *bug for bug* is a project in its own
right. The other compat symlinks (`gzip`, `xz`, `zstd`, `unzip`…) have small,
well-understood surfaces; `tar` does not.

### Network transport

`stuffr` reads stdin and files. It does not speak HTTP, FTP, S3, or anything else.
`curl … | stuffr cat -` composes perfectly well, and the whole point of the
streaming ladder is to make that pipeline work — which is precisely why the tool
does not need its own client, retry logic, credential handling, or TLS
dependency.

### Adjacent problems that are not compression

Each of these is a legitimate tool; none of them is this tool.

- **Delta and patch formats** — bsdiff, xdelta, courgette. Different problem
  (difference between two known inputs), different interface.
- **Deduplicating backup formats** — borg, restic, zpaq, dar. These are backup
  *systems*: chunk stores, indexes, retention policy, repository state. Reading
  one means implementing its whole data model.
- **Disk and VM images** — VHD, VMDK, qcow2, partition tables, LVM. squashfs and
  ISO are in scope because they are how software is *distributed*; general disk
  imaging is virtualisation tooling.
- **Filesystem archivers with live state** — anything requiring a running daemon,
  a lock, or a mounted volume to interpret.

### Research-grade compressors

PAQ, cmix, and the rest of the top of the Hutter Prize leaderboard. Excellent
ratios at runtimes measured in hours per gigabyte and memory in the tens of
gigabytes. Nobody can use them for the things `stuffr` is for. (A `--max` mode using
Zopfli for deflate is on the wishlist — that one is merely slow, not unusable.)

### Self-extracting executable generation

Reading an SFX archive by finding the payload after the stub is in scope.
*Emitting* one means shipping executable stubs per target platform, and a tool
that generates executables is a fundamentally different security proposition.

### A GUI, a TUI, or a file manager

`stuffr` is a library and a CLI. It is designed to be a dependency, so anyone who
wants a GUI has a good foundation to build one on — separately.

---

# Part 2 — Wishlist

Wanted, not scheduled.

## Streaming and random access

- **Indexed / seekable formats** — seekable-zstd, bgzip + `.gzi`, xz block
  indexes. These are the honest fix for the ladder's compromises: a real index
  means random access *and* parallel decode on a format that otherwise offers
  neither. Probably the highest-value item on this list.
- **`stuffr mount`** — FUSE mount of any supported container. Falls out fairly
  naturally once `by_index` is solid.
- **Multi-volume and split archives** — `.z01`/`.zip`, `.part1.rar`, `.001`.
  Needs a source abstraction that spans files, which the ladder could grow into.
- **Resumable extraction** — checkpoint and continue a partial extract.

## Search

- **`stuffr grep`** — built-in search across entries, parallel over the governor's
  lease pool, with entry-name prefixes and the usual context flags. The original
  motivation for the streaming work was piping to an external grep; doing it
  in-process avoids a full decode-and-copy per entry and can skip entries by
  metadata before decompressing them at all.

## Governor

- **Adaptive load backoff** — watch load average / pressure stall information and
  grow or shrink active workers while running. Deferred because it is genuinely
  hard to test deterministically, and a conservative static budget already solves
  most of the "don't wreck the server" problem.
- **`ionice` / I/O priority** alongside `--nice`.
- **Per-invocation budget persistence** — remember a good budget per machine.
- ~~**`--memory-limit` reaching the codec layer beneath a container.**~~
  **Done** — closed by the Phase 2 final review (finding C1). This note used
  to say the layer was "bounded only by `--max-ratio` today", which was
  factually wrong and dangerously so: `--max-ratio` counts decoded OUTPUT
  bytes, and the allocation it needed to bound (a pure xz/lzma/lzip
  dictionary, sized from a value the file declares in its own header)
  happens BEFORE any output exists, so that flag could never see it. The
  layer was in fact bounded by nothing at all, and a 336-byte `.tar.lz`
  declaring a 512 MiB dictionary drove hundreds of MB of RSS through
  `list`, `test` and `cat`, all exiting 0. `resolve_chain_deep_with` now
  takes `DecodeOpts`, and `--memory-limit` is accepted and honoured on
  `list`, `test`, `cat` and `unpack -C`.

## Formats — codecs

- LZO, LZFSE and LZVN (Apple), deflate64 (decode), Zopfli as a `--max` deflate mode
- zstd dictionary training (`--train`) and dictionary reuse
- Blosc / bitshuffle for numeric arrays
- LZSS and LZW variant zoo (`refpack`, `LZ4HC` tuning, `lzip` `.lz`)
- `lrzip` / `rzip` long-range preprocessing

## Formats — containers

- **7z, MS CAB, squashfs, ISO 9660 and RAR** — deferred from Phase 2's
  original scope. Each needs its own design cycle: 7z's solid blocks and
  index layout, squashfs and ISO's random-access filesystem-image shape, and
  RAR's read-only licence constraint (already permanent, see Part 1) are
  each a different problem from the four containers Phase 2 shipped.
- **Route `zip`'s per-entry codecs through stuffr's own codec registry**,
  rather than through the `zip` crate's bundled ones. This closes the
  pure-tier zstd-in-zip gap (`README.md`'s Build tiers section) and restores
  strict codec/container orthogonality — right now `zip` is the one format
  where the container and its codecs are not independently swappable.
- **cpio `odc` and `crc` variants.** Phase 2 shipped `newc` only.
- **Package formats as recognised profiles** — `.deb` (ar), `.rpm` (cpio),
  `.apk`/`.jar`/`.whl` (zip). Mechanically already readable; the value is
  *metadata awareness* (show the control file, the spec, the manifest) rather
  than new parsing.
- **Encrypted archive read** — AES-encrypted zip, 7z AES. Read only; see Part 1.
- Retrocomputing formats: Amiga `.dms`, Atari, CP/M, `.ALZ`, `.EGG`,
  `.BH`, `.PAK`, `.SQZ`, `.UC2`, `.HA`, `.YZ1`, `.PMA`.
  **Amiga/MS `.lzx` was on this list and is not any more** — Phase 3b deferred
  it to Phase 3c alongside StuffIt's older methods, so it is scheduled rather
  than excluded. What holds it back is evidence, not appetite: there is no
  second implementation and no obtainable tool, so a fixture and its expected
  contents would both come from the one crate being tested.
- WIM, DMG (as distribution formats rather than disk images)
- WARC, and `.tar.zst` variants with sidecar indexes

## Packing

Phase 2c gave `pack` a directory walk and one-step container-over-codec
composition. Three gaps it left open, each because closing it is a design
question rather than an omission:

- **Hardlink deduplication.** Two names for one inode currently pack as two
  independent files, with a fidelity warning saying so. Storing the second as
  a link needs three things, not one: an inode→first-name map held across the
  whole walk, an `EntryKind::Hardlink` that does not exist yet (`EntryKind` is
  `File`/`Dir`/`Symlink`/`Other` today), and a per-container capability bit
  beside `stores_dirs`/`stores_symlinks`, since `zip` and `ar` have no
  hardlink concept to write it into.
- **mtime normalisation for cross-machine reproducibility.** The same tree
  packs to the same bytes on one machine; it does not across two, because the
  entries carry real mtimes. A `--mtime`/`SOURCE_DATE_EPOCH` clamp would fix
  that, and it trades away fidelity to do it — which of the two is the default
  is exactly the decision that needs a spec.
- **`--exclude` and ignore-file filtering.** No way to leave `target/` or
  `.git/` out of a walk. Deferred because the interesting part is not the flag
  but the pattern dialect (glob vs. path-anchored, `.gitignore` semantics,
  whether an excluded entry is a fidelity warning or silent), and picking one
  casually is how a tool ends up with three.
- **The write-side plan is materialised whole, and is unbounded.**
  `entries.rs`'s `create_archive` walks every named path to completion and
  holds the entire result in memory — a `Vec<WalkItem>` plus a `HashSet` of
  every entry name for the duplicate check — before a single byte of the
  archive is written. `WalkItem` is 192 bytes measured, and each one also owns
  its entry name on the heap, the entry's full source `PathBuf`, and a second
  copy of the name in the `HashSet`: call it 400 bytes an entry. A
  million-file tree therefore costs a few hundred MB of RSS before the
  destination is even opened, and `--memory-limit` does not see it (that flag
  bounds the codec's worker count on encode and its allocation on decode, not
  this).
  It is deliberate and load-bearing today rather than merely unnoticed: the
  whole plan existing up front is what lets every input be validated before
  the destination is touched, what lets the output be recognised and excluded
  from its own walk, and what makes the duplicate-name refusal a pre-flight
  check instead of a failure halfway through a written archive. Streaming the
  walk would have to give up or re-engineer each of those, which is a design
  question, not an optimisation — and the bound that matters (name
  collisions) needs a set of names whatever the traversal looks like.

## Ergonomics

- Progress bars and ETA, suppressed when not a TTY
- Shell completions (bash, zsh, fish) and generated man pages
- `stuffr bench` — compare formats and levels on real input, report the ratio and
  throughput trade-off
- `--verify-sha256` and manifest emission on pack
- Better `stuffr info` output: entropy estimate, "this is already compressed, don't
  bother" advice
- `tar` compat symlink (see Part 1 for why it is not in v1)
- **A structured `Chain` type for `info --json`.** Today `info` reports the
  resolved chain as prose; a typed, serialisable `Chain` (container, codec,
  and how they stack) would let `--fidelity=json` consumers walk it
  programmatically instead of parsing text, and the cross-container
  `convert` below would consume the same type to plan its own reads and
  writes. (Deleted by accident in `5715b8b`, which added the `stere` entry
  immediately below it; restored by the Phase 2c final review.)
- **`stere`** (<https://crates.io/crates/stere>, source at `../stere`), a
  structure-aware searchable archive format for log files, developed in-house.
  It splits input into independently decodable blocks, extracts message
  templates into integer and string columns, and carries an archive-wide
  dictionary, trigram block filters and timestamp pruning. Magic is `STERE\0`
  at the head with a `STERETLR` trailer; round-trip is byte-exact.

  **Scope, decided:** `create` and `unpack` only. `stere grep` and the
  trigram/timestamp filters are deliberately NOT in scope — the `Container`
  trait knows about entries and nothing about searching inside them, and
  growing it a search capability is a design cycle that this does not need.
  stuffr would read and write stere archives; `stere` itself remains the tool
  for searching them. That is the whole goal here: widen format support so a
  stere archive is not a file stuffr has to refuse.

  It registers as a `FormatKind::Container`, and two parts fit stuffr's
  existing shapes without new machinery: a trailing index puts it in the same
  fidelity family as zip, which Phase 2 already built (`trailing_index`,
  `TrailingIndexUnread`), and per-block codecs map onto `EntryMeta::codec`.

  Three constraints remain, and none is a blocker:

  1. **MSRV, containable.** stere declares `rust-version = "1.95"` against
     stuffr's `1.88`. That sounds like a seven-version jump to the support
     floor, and it is not: `rust-toolchain.toml` already pins **1.95** for
     local development, and an optional `stere` feature kept out of `pure`
     leaves a default build's graph — and therefore its floor — untouched,
     exactly as `c-backed` does for the C crates. The real cost is one CI
     edit: the `msrv (1.88)` job runs `cargo build/test --workspace
     --all-features`, which would pull stere in at 1.88 and fail. That job
     needs an explicit feature list rather than `--all-features` before
     stere can be added to `full`.
  2. **Purity.** stere pins `zstd = "0.13"`, which is `zstd-sys` and a C
     compiler, so it belongs under `c-backed`. The `purity` CI job greps the
     pure graph for `zstd-sys` and fails if it appears, which already
     enforces this. Worth checking first: stuffr's own default zstd is
     `ruzstd`, pure, so a `full` build would contain two zstd
     implementations — not a conflict, but it should be a deliberate one.
  3. **It memory-maps.** `stere-core/src/reader.rs` does
     `unsafe { Mmap::map(&file) }`, so it needs a real seekable file and
     cannot read a pipe. The stream ladder exists precisely for this: stere
     declares `Rung::Exact` only, and `Spilled` stages a piped archive to
     disk first. No new machinery, but measure the spill cost before
     promising it — a log archive is exactly the thing someone pipes.

  Wanted because it is ours, and because with `grep` out of scope the
  remaining work is an ordinary container registration plus one CI edit.
  Not scheduled only because the phases ahead of it are.

- `stuffr convert IN OUT`, taking the destination as a second positional and
  inferring both formats from the filenames, alongside the `convert IN -o OUT`
  already planned for Phase 5. Wanted for the case that prompted it: an archive
  arrives in one format and has to go out in another —
  `stuffr convert logfile.tgz logfile.zip`.

  This is a larger job than the planned `convert`, and the two should not be
  conflated. That one is codec-level recompression with the container held
  fixed (`.tar.gz` → `.tar.zst`), which the streaming design already supports.
  Crossing *container* formats means reading entries out of one container and
  writing them into another, so it could not land before containers were in
  the tree at all — Phase 2 has now put them there, but this is still
  unscheduled work of its own. A `.zip` destination also carries its own
  constraint:
  the central directory needs per-entry sizes the stream has not produced yet,
  which is the same tension the ZIP-on-a-pipe contract test exists to pin
  down — so "without staging to disk" may not survive for every format pair,
  and which pairs it survives for is part of what the spec has to settle.

## Metadata fidelity

- Extended attributes, ACLs, sparse files, hard link detection
- macOS resource forks and `com.apple.*` xattrs
- High-resolution and pre-1970 timestamps
- Owner/group name preservation rather than numeric-only

## Platform and packaging

- WASM target for the `pure` feature set — a browser-side archive reader is a
  genuinely useful thing to have from this codebase
- `no_std` support for the simpler codecs
- Static musl builds and Homebrew / distro packaging

## Architecture

- **Out-of-tree plugin loading.** Architecture option C from the design, deferred
  deliberately: dynamic dispatch across a stable ABI is real work and there are no
  third-party format authors yet. Revisit if that changes.
- Solid-block reordering optimisation on 7z write (group similar files)
- Content-defined chunking for better dedup-friendly output

---

## Proposing a change

Adding to Part 2 needs only a rationale. Promoting something out of Part 2 means
it gets a spec, and moving something into Part 1 means writing down *why* — the
constraint or the trade-off — not just the conclusion.
