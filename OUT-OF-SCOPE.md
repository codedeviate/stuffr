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

## Formats — codecs

- LZO, LZFSE and LZVN (Apple), deflate64 (decode), Zopfli as a `--max` deflate mode
- zstd dictionary training (`--train`) and dictionary reuse
- Blosc / bitshuffle for numeric arrays
- LZSS and LZW variant zoo (`refpack`, `LZ4HC` tuning, `lzip` `.lz`)
- `lrzip` / `rzip` long-range preprocessing

## Formats — containers

- **Package formats as recognised profiles** — `.deb` (ar), `.rpm` (cpio),
  `.apk`/`.jar`/`.whl` (zip). Mechanically already readable; the value is
  *metadata awareness* (show the control file, the spec, the manifest) rather
  than new parsing.
- **Encrypted archive read** — AES-encrypted zip, 7z AES. Read only; see Part 1.
- Retrocomputing formats: Amiga `.dms`/`.lzx`, Atari, CP/M, `.ALZ`, `.EGG`,
  `.BH`, `.PAK`, `.SQZ`, `.UC2`, `.HA`, `.YZ1`, `.PMA`
- WIM, DMG (as distribution formats rather than disk images)
- WARC, and `.tar.zst` variants with sidecar indexes

## Ergonomics

- Progress bars and ETA, suppressed when not a TTY
- Shell completions (bash, zsh, fish) and generated man pages
- `stuffr bench` — compare formats and levels on real input, report the ratio and
  throughput trade-off
- `--verify-sha256` and manifest emission on pack
- Better `stuffr info` output: entropy estimate, "this is already compressed, don't
  bother" advice
- `tar` compat symlink (see Part 1 for why it is not in v1)

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
