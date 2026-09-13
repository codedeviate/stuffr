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

> **One manual step.** Cargo will not let a *dependency* version inherit from
> the workspace, so the three inter-crate entries carry the number literally:
> two in `[workspace.dependencies]` (root `Cargo.toml`) and one in
> `crates/stuffr-cli/Cargo.toml`. Bump those together with the workspace
> version. `grep -rn 'version' Cargo.toml crates/*/Cargo.toml | grep -v
> rust-version` should show every occurrence reading the new number at once —
> a missed one fails the build, but the recipe is worth running anyway,
> because the failure is confusing when it happens.

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
| `0.4.0` | Phases 3–4 — legacy read and write, fuzzed. |
| `0.5.x` | Phase 5 — compatibility symlinks, `convert`, polish. |
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
of the workspace). Three targets, each `#![no_main]` and driven by
libFuzzer through `cargo fuzz`:

| Target | Covers |
|---|---|
| `codec.rs` | One codec's decoder, fed raw bytes. A selector byte picks the format from [`CODEC_SLOTS`](#the-slot-tables-are-append-only) so one corpus exercises every registered codec. |
| `container.rs` | One container's reader, both ladder rungs — the selector's high bit picks seekable vs. `ForwardOnly` so both walk paths get fuzzed, not just the seekable one. Also runs an independent EOCD re-parse and a second forward-only walk as cross-checks (see the module doc for why each is not redundant with the honesty oracle below). |
| `chain.rs` | No selector at all — arbitrary bytes go straight at format detection (`resolve_chain_deep`) and `entries::list`'s container dispatch, the DETECTION layer a real `curl \| stuffr cat -` goes through, and where a silent wrong-format bug once lived. It stops there: no target runs `ops::decompress` itself, so `cat`'s own payload read is not covered by any of the three. |

Every decode path in all three is bounded (`DecodeOpts::memory_limit`,
a capped output read) for the same reason the codec's own conformance
harness bounds decode: an unbounded pre-flight allocation or an
unconditional `read_to_end` on a decompression bomb would turn every
subsequent run into an OOM or a false "crash" instead of a finding.

### The oracle lives in the library, not in the targets

`stuffr-core/src/honesty.rs` holds the four invariants the targets assert —
`check_error_is_classified`, `check_entry_size`, `check_entry_count`,
`check_fidelity_claim` — re-exported through `stuffr_core::testing` (gated
`#[cfg(any(test, feature = "testing"))]`) rather than written inline in a
fuzz target. The reason is structural, not a style preference: **a fuzz
target's checks cannot be unit-tested, so a harness that runs clean is
indistinguishable from one whose invariants are vacuous** — "ran 30 seconds,
found nothing" looks identical either way, whether the target is genuinely
clean or the assertion inside it never fires. Because the four functions
live in an ordinary library module, each has a `mod broken_honesty` double
proving it *can* fail — the same `broken_codecs`/`broken_containers` pattern
the conformance harnesses already use — so a vacuous check is caught the
same way a vacuous conformance property would be.

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
built to cover eleven codecs quietly stops covering one of them.

### Corpus and running locally

The corpus is generated, not committed (`fuzz/.gitignore`'s `/corpus`):

```bash
make fuzz-corpus   # (re)generate fuzz/corpus/{codec,container,chain}
make fuzz          # short, seeded smoke pass — the local equivalent of CI's fuzz-smoke job
```

`make fuzz` mirrors `ci.yml`'s `fuzz-smoke` job — same fixed `-runs=2000
-seed=1` budget per target, same non-zero-execution-count check so a target
that silently returns early on every input can't pass by doing nothing. (Not
*exactly*: the CI copy ends its grep pipeline with `|| true`, because GitHub
runs that block under `bash -e -o pipefail` where a no-match grep would abort
the script before the check it feeds. The Makefile runs under a plain `sh`
and must not. Both files say so; do not tidy either into matching the other.)

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
