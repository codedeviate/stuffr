# Contributing to stuffr

## Setup

```bash
make hooks   # once per clone — installs the commit-msg hook
make check   # the full gate: fmt, lint, test, release build
```

`make hooks` sets `core.hooksPath`, which git does not do for you: hooks live
in `.git/hooks` by default and are never cloned, so an uninstalled hook is a
hook that silently does nothing.

## The gate

`make check` is this project's Definition of Done, made executable:

| Step | Command |
|---|---|
| Format | `cargo fmt --all --check` |
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Test | `cargo test --workspace --all-features` |
| Release | `cargo build --release --workspace` |
| Feature floor | `cargo build -p stuffr-core --no-default-features` |

Run it after every change, not just before committing. The last step is not
redundant with the first build: it proves `stuffr-core` still compiles with no
optional features, which is the guarantee behind "installing `stuffr` needs no C
toolchain".

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/). The `commit-msg`
hook enforces the shape of the subject; it never judges the prose.

```
<type>[(scope)][!]: <description>

[body]

[footers]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
`ci`, `chore`, `revert`.

**Scopes:** `core`, `formats`, `cli`. Omit the scope for workspace-wide changes.

A trailing `!` before the colon marks a breaking change, as does a
`BREAKING CHANGE:` footer. Subjects are capped at 72 bytes — put detail in the
body, which has no limit and is where reasoning belongs anyway.

```
feat(core): add seekable zstd frame index
fix(cli): exit 2 on an unknown verb, not 1
feat(core)!: return Box<dyn Source> from Codec::decoder
docs: record the Phase 1 carry-forward list
```

Git's own generated subjects — merges, reverts, `fixup!`, `squash!`, `amend!` —
are exempt, because their shape is fixed by git rather than by us and rejecting
them would break rebasing outright.

## Versioning

[Semantic versioning](https://semver.org/), with all four crates moving in
**lockstep**. `stuffr` re-exports `stuffr-core` wholesale, so independent
version numbers would be fiction.

The version lives in exactly one place — `version` under `[workspace.package]`
in the root `Cargo.toml` — and each crate inherits it with
`version.workspace = true`.

> **FIVE manual sites, not four.** Cargo will not let a *dependency* version
> inherit from the workspace, so the three inter-crate entries carry the
> number literally: two in `[workspace.dependencies]` (root `Cargo.toml`) and
> one in `crates/stuffr-cli/Cargo.toml`. Bump those together with the
> workspace version — four `Cargo.toml` sites in all. `grep -rn 'version'
> Cargo.toml crates/*/Cargo.toml | grep -v rust-version` should show every
> occurrence reading the new number at once; a missed one fails the build,
> but the recipe is worth running anyway, because the failure is confusing
> when it happens.
>
> **The fifth is `fuzz/Cargo.lock`, and that grep cannot see it** — it is a
> lockfile, not a manifest, and `fuzz/` is `exclude`d from the workspace, so
> no workspace `cargo` command resyncs it. It went stale once, at `0.3.1`
> against manifests reading `0.4.0`, and nothing said so until somebody ran
> `make fuzz`.
>
> Since Phase 3c the gate catches it instead of a human remembering: `make
> lint` runs `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets
> --locked`, and `--locked` fails at exit 101 the moment the lockfile and the
> manifests disagree. It refuses rather than repairs, deliberately — so the
> sequence is: bump the four manifests, resync the lockfile
> (`cargo metadata --manifest-path fuzz/Cargo.toml >/dev/null`, or `make
> fuzz`, either of which rewrites it), then `make check`, and commit
> `fuzz/Cargo.lock` with the bump.

### Before publishing a bump

One command checks all four crates, and it is the one to run:

```bash
cargo publish -p stuffr-core -p stuffr-formats -p stuffr -p stuffr-cli --dry-run
```

Cargo resolves the inter-crate order itself, packages all four, verify-builds
each, and aborts every upload. Measured at `0.4.2`, with the version not yet
on crates.io: **exit 0**.

Running the crates one at a time instead is what the older note recommended,
and it does not work at a bump: `cargo publish -p stuffr-formats --dry-run`
alone fails with `failed to select a version for the requirement stuffr-core
= "^<new>"` until the new `stuffr-core` is actually live. That failure is
expected rather than a defect — but it means three of the four crates are
never verify-built, which is precisely the coverage the command above gives
you. Reach for `-p` on its own only to isolate a failure it reported.

The real publish still goes in order: `stuffr-core`, `stuffr-formats`,
`stuffr`, `stuffr-cli`.

### While below 1.0

Under semver, `0.y.z` makes no compatibility promises, and `0.0.z` makes none
at all — which is honest for a foundation whose traits are still moving. So:

- **`0.0.z`** — anything may change, including trait signatures. Bump `z` for
  any release.
- **`0.y.0`** — reserved for the milestones the design document defines.
  Reaching one is a deliberate act, not an accident of accumulation.

### Milestones

These come from the design specification and are the reason Phase 0 shipped as
`0.0.1` rather than `0.1.0`:

| Version | Contents |
|---|---|
| `0.0.z` | Phase 0 — core abstractions, validated against mock formats. No real formats. |
| `0.1.0` | Phase 1 — the modern codecs, parallel encode and the thread governor. Streams and single files, no containers. |
| `0.2.0` | Phase 2 — containers, and the ZIP-on-a-pipe contract test. |
| `0.3.0` | Phase 2c and its follow-ups — write-side composition (`pack -o bundle.tar.gz` in one pass) and directory walking, so the read/write symmetry claim becomes true for archives; plus entry selection by index (`list`'s index column, `cat --index`, `unpack --index`), `list` reporting fidelity and gaining `--strict-fidelity`, the declaration of zip central-directory records shadowed by a duplicate name, and the guard refusing a pack that would replace a good archive with an empty one. |
| `0.4.0` | Phase 3a–3b — the fuzzing harness, the honesty oracle and the exit-code corrections it found, plus three read-only legacy formats (`compress`, `lha`, `arj`), each proven against the fixture-driven conformance harness Phase 3b's Task 1 introduced for read-only containers. |
| `0.5.0` | Salvage Stage 1 — the `salvage` verb and zip's central-directory recovery scan (`SalvageScan`, `Candidate`, `SalvageStatus`, `salvage_all`), reversing Phase 2's "declared, not recovered" ruling for zip: the shadowed-record parse that ruling declined to build now serves recovery, not only `list`'s warning. |
| `0.5.x` (later) | Remaining Salvage stages (a `Complete` tier genuinely exercised by tar/cpio/ar, not only zip) and Phase 5 — compatibility symlinks, `convert`, polish. Not yet claimed by a single number; whichever lands next takes the next open one. |
| `1.0.0` | Reserved for feature-complete, not for any single phase — no earlier milestone claims it. |

This table was revised after Phase 1: the original plan put legacy read/write
at `1.0.0` and treated it as the last stop. Fuzzed legacy symmetry is a real
milestone, but it is not the same claim as "feature-complete," so it moved
down and `1.0.0` was freed to mean what it says.

It was revised a **second** time, after Phase 2c, and for a different kind of
reason — not a re-reading of what a milestone means, but a version number the
work forced. Phase 2c changed `Container::create` and `ArchiveWrite::finish`,
which is a breaking change to `stuffr-core`, and Cargo treats the middle
number of a `0.x.y` as the major: `0.2.1` would have presented that break to
every dependent as compatible. So Phase 2c took `0.3.0` — a milestone that had
been promised to legacy read/write — and everything below it shifted down one.
A milestone is still a deliberate act; this is the case where the compatibility
rules, rather than the plan, decide which number it gets.

The `0.3.0` **row** was then widened, though its number was not. Work kept
landing after the bump and before the first crates.io publication — entry
selection by index, `list`'s fidelity reporting, the zip shadowed-record
declaration, the empty-plan guard — and since nothing had shipped, the honest
move was to redefine what `0.3.0` contains rather than to let the first release
notes describe a subset of what the tag actually carries.

The `0.4.0` **row** was revised a **third** time, and for the same reason
`0.3.0`'s was widened rather than renumbered: the row used to promise "legacy
read and write", and write support is real, undone work rather than a
formality. Extending `Codec::encoder` and `Container::create` to `compress`,
`lha` and `arj` needs its own fixtures, its own interop checks against real
encoders, and its own review cycle — exactly as read did across Tasks 1-7 —
and shipping it inside `0.4.0` would mean either delaying the read-only
formats that were already fuzzed and reviewed, or claiming write coverage the
test suite does not have. So `0.4.0` now says only what actually shipped, and
legacy write becomes its own cycle — Phase 3c, which landed as **`0.4.2`**.
(The plan said `0.4.1`; that number was taken in the meantime by the
`xz-pure` index-bomb fix, an unrelated single-commit patch cut before Phase
3c's first task. The phase moved to the next patch rather than displacing a
tag that already existed.)

**Phase 3c carries ARC and ZOO as well**, and that belongs here rather than
only in a plan outside the repository, because a reader of this repo would
otherwise conclude the two were dropped. They were scoped into Phase 3b
originally, on a single crate (`unarc-rs`) that would have served both; that
direction was abandoned in favour of a per-format crate for each of the three
formats that shipped, and ARC and ZOO moved with it into 3c rather than out
of the project. **`grep -rn unarc` now finds plenty, and none of it is that
direction**: `unarc-rs` is still disqualified as a DEPENDENCY (rustc 1.95,
vendored C++, a second zip/tar stack — the reasons are in
`fixtures/legacy/MANIFEST.md`), and what the tree carries is its MIT/Apache
test corpus borrowed as bytes plus prose explaining why the code was not.
Nothing imports or links it; `Cargo.lock` has no such entry. So 3c is: write
support for `compress`/`lha`/`arj`, plus READ support for ARC and ZOO. ARC and
ZOO's read support, `compress`'s write support (Task 5 — the first of the
three write tasks to land), `lha`'s (Task 6, a `-lh5-` encoder verified
against `lhasa`) and `arj`'s (Task 7, a store-only encoder with **no
external witness at all** — no `arj`/`unarj` binary is obtainable, so
byte-level assertions against the published spec's own constraints stand in
for the reference tool the other two have) have all now shipped, each with
its framing written from scratch. `arc` and `zoo` are what still refuses to
write.
That is a
PATCH, not a milestone, because it is additive to traits that already exist
(`Container::create`, `Codec::encoder` are both already part of the public
surface; Phase 3c gives three more formats a real implementation of each, it
does not change either trait's shape) — a phase's own work is not
automatically a milestone, the same distinction that kept `0.3.1` (three
exit-code fixes, no capability change) a PATCH against `0.3.0`'s own row
above it.

The table was revised a **fourth** time, for Salvage Stage 1. `0.5.x` had
stood for Phase 5 (compatibility symlinks, `convert`, polish) since the table
was first written — a promise made before Salvage existed as a cycle at all.
**The promise is not holy**: it has already moved three times as scope moved,
and a name on a row is not a reason to ship the wrong work under it. Salvage
Stage 1 adds a CLI verb (`salvage`) and new public surface in `stuffr-core`
(`SalvageScan`, `Candidate`, `SalvageStatus`, `salvage_all` and their
neighbours) — new capability, not a fix to an existing one, so it claims
`0.5.0` on the same reasoning `0.4.0` claimed its own three new formats.
Phase 5's original content moves to a later, not-yet-numbered `0.5.x` row,
alongside whichever later Salvage stage lands next (a `Complete` tier
genuinely exercised by tar/cpio/ar, per the design's own Stage 3 — Stage 1
never exercises it, since zip always carries a CRC-32). Neither has landed,
so pinning either to an exact number now would be the same mistake that
moved `0.4.0`'s row twice already: claiming a number before the work behind
it is real.

After 1.0, normal semver applies: breaking changes to any public API in
`stuffr-core` or the `stuffr` facade require a major bump.

## `#[non_exhaustive]`

Enums carry it. Structs do not.

The asymmetry is principled rather than stylistic, and it follows from what
each kind of addition breaks downstream:

- **Adding a variant to a public enum** breaks every exhaustive `match` in
  every dependent crate. `#[non_exhaustive]` forces a wildcard arm up front,
  so the addition is not a breaking change. `Error`, `Fidelity`, `EntryKind`
  and `Chain` all carry it, and all four are expected to grow — `EntryKind`
  gains `Hardlink`, `CharDevice`, `BlockDevice`, `Fifo` and `Socket` when tar
  and cpio arrive.
- **Adding a field to a public struct** does not break `..Default::default()`,
  so the attribute buys nothing there — and it costs something real. A
  `#[non_exhaustive]` struct cannot be built with literal syntax from another
  crate at all, so `CodecCaps { encode: true, ..Default::default() }` in
  `stuffr-formats` would stop compiling. That punishes every format author to
  solve a problem we do not have.

Capability and options structs therefore stay literal-constructible, and gain
**named constructors** instead — `CodecCaps::round_trip()`,
`ContainerCaps::read_only()`, `FormatMeta::codec()`. A future field then
touches the constructors rather than every `caps()` implementation, which is
the same protection by a cheaper route.

**The exception: a struct that is only ever *destructured* downstream, never
*constructed*.** `ladder::Resolved` is the case — it is built exclusively by
`stuffr_core::ladder::resolve`, and every consumer (every `Container::open`
impl, in every format crate) receives one and destructures it:
`let Resolved { source, rung, report, .. } = resolved;`. No downstream crate
ever writes `Resolved { .. }` as a constructor, so the cost that exempts the
capability structs — breaking `Foo { a, ..Default::default() }` in a
dependent crate — does not apply here. Adding a field to `Resolved` would
instead break every one of those destructures at once, which is exactly what
`#[non_exhaustive]` prevents (a struct pattern must end in `..` to match a
`#[non_exhaustive]` struct from another crate). So `Resolved` carries the
attribute, and the reference destructure ends in `..` for the same reason a
`match` on a non-exhaustive enum ends in a wildcard arm. The rule for structs
is therefore: **carry it if downstream only ever destructures; skip it if
downstream ever constructs.**

**Two structs have grown a field under this rule, and the two were handled
differently on purpose.** `CodecCaps` gained `truncation_undetectable` in
Phase 3b; `ExpectedEntry` gained `stored_crc` in Phase 3c Task 1. Each is a
public field added to a public struct with no `#[non_exhaustive]`, which is
precisely the change this section says breaks an external crate constructing
one with an exhaustive literal — and since `0.3.1` these crates have been
**published on crates.io**, so "external crate" is not hypothetical.

- **`CodecCaps` and `ContainerCaps` stay open**, and that is measured rather
  than assumed: all **23** of their literals in `stuffr-formats` — 15
  `CodecCaps` and 8 `ContainerCaps` — end in a `..` tail
  (`..CodecCaps::round_trip()`, `..Default::default()`), zero bare, so a new
  field is already absorbed for free at every site. (This said "46" until
  Phase 3c's final review re-derived it. The naive
  `grep -rn 'CodecCaps {\|ContainerCaps {'` answers 48: 23 literal openings,
  23 `-> CodecCaps {` / `-> ContainerCaps {` **function signatures** one line
  above them, and 2 doc-comment lines. Whoever measured it excluded the doc
  comments and then counted every literal twice. The conclusion never
  changed; the figure is quoted as a measurement, so it has to be one.) Closing them would forbid `..`
  construction from another crate outright — the exact cost the paragraphs
  above refuse to impose on format authors.
- **`ExpectedEntry` and `ContainerFixture` are now closed** —
  `#[non_exhaustive]` plus const constructors (`ExpectedEntry::new` /
  `with_crc`, `ContainerFixture::new`), landed in the same release that added
  the field. They are the opposite shape from a capability struct: three
  fields, all mandatory, two meaningful spellings, no subset to express, so
  nothing is lost by closing them.

**The deciding rule, then, is the field count and whether callers set
subsets** — not "struct versus enum". And **the moment to close one is the
release that changes it**, while the affected population is known. For
`0.4.2` that population was measured at zero external reverse dependencies
on `stuffr-core` (crates.io reverse-dependency API, verified 2026-09-16), and
none enabling `testing`; a later release cannot assume the same, which is why
the check is dated wherever it is recorded.

### Which enums are open, which are closed

"Enums carry it" above is not quite universal either: four public enums —
`Rung`, `StreamPolicy`, `FormatKind`, `SpillPolicy` — do **not** carry
`#[non_exhaustive]`, deliberately. The distinction is whether the enum names
an open-ended set that formats will keep adding to, or a closed domain fixed
by the crate's own design:

- **Open — carry the attribute.** `Error`, `Fidelity`, `EntryKind`, `Chain`.
  Each is expected to grow as formats are added: `EntryKind` gains
  `Hardlink`, `CharDevice`, `BlockDevice`, `Fifo` and `Socket` when tar and
  cpio arrive, and `Fidelity` grows a variant for every new kind of loss a
  future format can produce.
- **Closed — no attribute, by design.**
  - `Rung` — the adaptive stream ladder has exactly four rungs
    (`Exact`/`ForwardOnly`/`Spilled`/`Degraded`); that is the ladder's whole
    design, not a partial list waiting for a fifth.
  - `FormatKind` — the codec/container dichotomy the crate is built on. A
    third kind would be a different architecture, not an addition.
  - `StreamPolicy`, `SpillPolicy` — user-facing choices, where an exhaustive
    `match` in a caller (e.g. a CLI flag mapping) is desirable rather than a
    hazard: the point is that the caller sees every option there is.

A closed enum can still gain variants later, but doing so is a deliberate,
documented redesign — the same bar `0.y.0` milestones already clear — not the
routine addition `#[non_exhaustive]` exists to absorb.

## Architectural constraints

Two rules hold across every phase. Both are load-bearing rather than stylistic,
and a change that breaks either needs a design decision, not a patch:

1. **`stuffr-core` has zero format dependencies.** No `flate2`, `zstd`,
   `bzip2`, `brotli`, `lz4`, `snap`, `xz` or `liblzma` — ever. That constraint
   is what makes the stream ladder and the thread governor testable against
   mock formats with no C toolchain and no real archives. Format
   implementations belong in `stuffr-formats`.
2. **No `anyhow` in `stuffr-core`.** Errors are a typed `thiserror` enum,
   because callers need to `match` on `NotSeekable` and `FormatNotEnabled` to
   implement fallbacks. A boxed error would make that impossible.

## `unsafe`

The tree contains `unsafe` in exactly **two** places, both introduced in
Phase 2 and both the same shape:

| File | What | Why |
|---|---|---|
| `crates/stuffr-formats/src/tar.rs` | `Box::into_raw` / `&mut *ptr` / `Box::from_raw` in `TarRead` | `tar::Archive<R>` hands out `Entry<'a>` borrowing the archive; the `ArchiveRead` trait needs the archive and the entry in one struct |
| `crates/stuffr-formats/src/ar.rs` | the same trio in `ArRead` | `ar::Archive<R>`, same self-referential shape |

Each is a **self-referential struct**: an owning box leaked to a raw pointer
so a borrowed iterator can live beside the thing it borrows from, reclaimed
in `Drop`. There is no other `unsafe` anywhere in the workspace, and adding
a third place is a design decision, not a patch — reach for an owning API
(the way `cpio.rs` does, with a plain state enum and no `unsafe` at all)
before reaching for a raw pointer.

Rules for touching either region:

1. **Every `unsafe` block carries a `SAFETY:` comment** stating the
   invariant that makes it sound and what would break it. A block without
   one does not go in.
2. **Miri must pass before and after any change to those regions**, under
   both aliasing models. Both are Miri-clean today and nothing else
   protected that fact:

   ```
   make miri
   ```

   which runs `cargo miri test` for `stuffr-formats` under Stacked Borrows
   and again under Tree Borrows. CI runs the same job (`miri`), so a
   regression is caught even if a contributor forgets.
3. **Miri cannot spawn processes**, so the cross-implementation tests that
   shell out to `tar`, `ar`, `cpio`, `zip`/`unzip` and `lzip` are excluded
   from the Miri run by name (`--skip system_ --skip we_accept_`). Those
   tests exercise interop, not aliasing, and they are covered by the
   ordinary `make check`. Do not "fix" a Miri failure by widening that skip
   list to cover a test that really does exercise the pointer regions.
4. `make miri` is **not** part of `make check`. Miri is 10-50x slower than
   a native run, and the gate is already 35-60s; running it on every edit
   would change how the gate is used. Run it when you touch `tar.rs`'s or
   `ar.rs`'s pointer handling, and let CI run it the rest of the time.

## Fuzzing

Phase 3a added a fuzzing harness over the excluded `fuzz/` crate
(`build: add an excluded fuzz crate`, so it never affects a `cargo build`
of the workspace). Five targets, each `#![no_main]` and driven by
libFuzzer through `cargo fuzz`:

| Target | Covers |
|---|---|
| `codec.rs` | One codec's decoder, fed raw bytes. A selector byte picks the format from [`CODEC_SLOTS`](#the-slot-tables-are-append-only) so one corpus exercises every registered codec. |
| `container.rs` | One container's reader, both ladder rungs — the selector's high bit picks seekable vs. `ForwardOnly` so both walk paths get fuzzed, not just the seekable one. Also runs an independent EOCD re-parse and a second forward-only walk as cross-checks (see the module doc for why each is not redundant with the honesty oracle below). |
| `chain.rs` | No selector at all — arbitrary bytes go straight at format detection (`resolve_chain_deep`) and `entries::list`'s container dispatch, the DETECTION layer a real `curl \| stuffr cat -` goes through, and where a silent wrong-format bug once lived. It stops there: no target runs `ops::decompress` itself, so `cat`'s own payload read is not covered by any of the five. |
| `roundtrip.rs` | The WRITE side, added in Phase 3c Task 8 — the only target that runs an encoder at all. The input is the archive's CONTENT, not its bytes: a selector picks a writable slot (its high bit selects `CODEC_SLOTS` over `CONTAINER_SLOTS`; there is no ladder rung to choose when writing), the payload is written through it and read straight back, and the two must agree byte-for-byte. |
| `salvage.rs` | Added in Salvage Stage 1 Task 8 — the one target that treats arbitrary bytes as a damaged ARCHIVE rather than as content fed to a decoder or container reader. Spools its input to a real tempfile (salvage needs genuine random access) and calls the same `entries::salvage` path the CLI does, with no destination (`dest: None`), so it exercises parsing and verification honesty rather than the filesystem write path — already covered via `chain.rs`'s `entries::list`. Seeded from six hand-built zips (`SALVAGE_SHAPES` in `crates/stuffr/tests/fuzz_corpus.rs`): a healthy archive, two duplicate-name shapes (differing and byte-identical), a zeroed central directory, a truncated tail and a flipped payload byte. It ran **unseeded** until the Salvage Stage 1 final fix wave, and that was not a budget problem — see "Corpus and running locally" below for the measurement. |

Every decode path in all five is bounded (`DecodeOpts::memory_limit`,
a capped output read) for the same reason the codec's own conformance
harness bounds decode: an unbounded pre-flight allocation or an
unconditional `read_to_end` on a decompression bomb would turn every
subsequent run into an OOM or a false "crash" instead of a finding.
`roundtrip.rs` bounds the WRITE side too, and for the mirror reason:
`lha`'s encoder buffers roughly 8.4x its input before emitting anything,
which reaches `handle_alloc_error` — a SIGABRT carrying no stuffr message
— rather than any error this project could classify.

**A new target must be shown to complete an iteration, not assumed to.**
Phase 3a shipped a target that used `Error::from(io)` everywhere, so every
input produced `Error::Io` — exit 1 — which the oracle always refuses; it
had never completed a single iteration and looked exactly like a clean run.
`roundtrip.rs` was therefore checked the way `mod broken_codecs` checks a
conformance property: with its equality assertion temporarily sabotaged to
`got == content && content.is_empty()`, all eighteen writable slots
(twelve codecs, six containers) reach it and report *"same length but
different contents"* — which is only reachable when the real comparison
was true, i.e. when the round trip genuinely completed. Do the same for
the next target; an execution count alone does not distinguish the two
cases.

### The oracle lives in the library, not in the targets

`stuffr-core/src/honesty.rs` holds the five invariants the targets assert —
`check_error_is_classified`, `check_entry_size`, `check_entry_count`,
`check_fidelity_claim` (Phase 3a), and `check_salvage_claim` (Salvage Stage 1
Task 8) — re-exported through `stuffr_core::testing` (gated
`#[cfg(any(test, feature = "testing"))]`) rather than written inline in a
fuzz target. The reason is structural, not a style preference: **a fuzz
target's checks cannot be unit-tested, so a harness that runs clean is
indistinguishable from one whose invariants are vacuous** — "ran 30 seconds,
found nothing" looks identical either way, whether the target is genuinely
clean or the assertion inside it never fires. Because the five functions
live in an ordinary library module, each has a `mod broken_honesty` double
proving it *can* fail — the same `broken_codecs`/`broken_containers` pattern
the conformance harnesses already use — so a vacuous check is caught the
same way a vacuous conformance property would be.

`check_salvage_claim` is narrower than its four siblings by construction:
`SalvageStatus::Partial` is a unit variant in `stuffr-core`, so the oracle
can only ever refuse a false `Intact` claim (one made without checking a
checksum), never distinguish *why* an entry is `Partial` — that distinction
lives one crate up, in `stuffr::entries::PartialCause`, derived from a
second decode the core layer never runs. See `honesty.rs`'s own doc comment
on `check_salvage_claim` for the boundary this draws, and `salvage.rs`'s
module doc for the consequence it leaves open (a regression returning
`Partial` for a fully decodable entry, without ever comparing, would be
invisible to this oracle).

The first invariant, `check_error_is_classified`, guards `Error::exit_code`'s
`_ => 1` wildcard: hostile bytes may be refused, but never as exit 1, which
means "stuffr itself failed" rather than "the input was bad". It found a real
bug before the fuzzer had run once — `Error::NotSeekable` was falling through
to exit 1 despite being the *mandated* reply to `by_index` on a forward-only
source, so a valid archive read from a pipe was reporting failure for a
by-design refusal. It is now exit 3.

### The slot tables are append-only

`CODEC_SLOTS` and `CONTAINER_SLOTS` (`stuffr-core`'s `testing` module) map a
fuzz input's selector byte to a format name. **Append only — never reorder,
never remove; retire a slot by leaving it in place.** The ordering is the
wire format of every corpus seed on disk: a seed minimised against `bzip2`
is a seed whose selector byte, modulo the table's length, happens to land on
`bzip2`'s current index. Reorder the table and that same seed silently
starts feeding a different codec — nothing fails to tell you, and a corpus
built to cover twelve codecs quietly stops covering one of them.

### Corpus and running locally

The corpus is generated, not committed (`fuzz/.gitignore`'s `/corpus`):

```bash
make fuzz-corpus   # (re)generate fuzz/corpus/{codec,container,chain,roundtrip,salvage}
make fuzz          # short, seeded smoke pass — the local equivalent of CI's fuzz-smoke job
```

`make fuzz` mirrors `ci.yml`'s `fuzz-smoke` job — same fixed `-runs=2000
-seed=1` budget per target, same non-zero-execution-count check so a target
that silently returns early on every input can't pass by doing nothing. (Not
*exactly*: the CI copy ends its grep pipeline with `|| true`, because GitHub
runs that block under `bash -e -o pipefail` where a no-match grep would abort
the script before the check it feeds. The Makefile runs under a plain `sh`
and must not. Both files say so; do not tidy either into matching the other.)

**An unseeded target can execute cleanly and prove nothing, and `salvage`
did.** Its only oracle call, `check_salvage_claim`, fires on
`SalvageStatus::Intact` alone, and `Intact` requires a CRC-32 that matches
its payload — which random mutation from an EMPTY corpus will not produce.
So the assertion was unreachable by construction, not merely unlucky.
Measured before it was seeded: 100,000 runs plateaued at `cov: 217` with a
38-file corpus, and running the binary's own `salvage --list` over all 64
accumulated inputs produced **not one salvaged record** — no `Intact`, no
`Complete`, no `Partial`, no `Unverified`, anywhere. `make fuzz` reported
`target 'salvage': 2000 executions — OK` throughout, truthfully.

Measured after seeding, same budget: `cov: 574`, and 345 of 548 accumulated
corpus inputs produce at least one salvaged record with 117 reaching
`Intact`. This is the same lesson as "a new target must be shown to complete
an iteration" one section up, one level deeper: here the iterations DID
complete, they just never reached the check. The generator's own
`every_salvage_seed_produces_records_and_at_least_one_intact` test is what
keeps it that way — it runs the real engine over every seed rather than
counting files, because counting files is exactly the assertion that would
have passed on the empty state.

**A fixed `-runs` and `-seed` do not make either run deterministic, and a
green one is not proof of absence.** Measured on the `container` target with
the same seed and the same corpus, five identical re-runs: 3 of 5 found a
crash on one pass and 2 of 5 on the next. `-seed=` fixes libFuzzer's mutation
PRNG, not the order it walks the corpus directory or its entropic scheduling,
and both feed the mutator. The flakiness is **false-negative only** — a run
may miss a crash it found before, but it never reports one that did not
happen — which is what earns the job the right to block. So treat a crash
that will not reproduce from the echoed command as expected rather than as a
flaky test to be quieted: re-run it, or hand the artifact to `cargo fuzz run
<target> <artifact>`, which *is* deterministic. `ci.yml`'s Ruling G comment
carries the same measurement.

Neither `fuzz-corpus` nor `fuzz` is part of `make check`: `cargo
fuzz` needs the nightly toolchain the gate does not assume, and generating
the corpus writes real files under a gitignored directory rather than
something every edit should refresh. A slower, wall-clock-budgeted pass runs
weekly (and on demand) via `.github/workflows/fuzz-deep.yml`, independent of
`ci.yml`.

**A crash becomes an ordinary regression test, not a file left in
`fuzz/artifacts/`.** Reduce the crashing input, understand which of the four
invariants (or which codec/container property) it violates, and add it as a
named unit or CLI test the normal way — the artifact itself is not the
fix and is not meant to be committed.

## Testing

Test-driven: write the failing test, watch it fail for the reason you expect,
then make it pass. A test that has never failed has not been shown to test
anything.

Test output must be pristine — warnings in a passing run are a defect, not
noise to scroll past.
