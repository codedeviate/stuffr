# Contributing to stf

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
optional features, which is the guarantee behind "installing `stf` needs no C
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
| `0.3.0` | Phases 3–4 — legacy read and write, fuzzed. The read/write symmetry claim becomes true. |
| `0.4.x` | Phase 5 — compatibility symlinks, `convert`, polish. |
| `1.0.0` | Reserved for feature-complete, not for any single phase — no earlier milestone claims it. |

This table was revised after Phase 1: the original plan put legacy read/write
at `1.0.0` and treated it as the last stop. Fuzzed legacy symmetry is a real
milestone, but it is not the same claim as "feature-complete," so it moved to
`0.3.0` and `1.0.0` was freed to mean what it says. After 1.0, normal semver
applies: breaking changes to any public API in `stuffr-core` or the `stuffr`
facade require a major bump.

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

## Testing

Test-driven: write the failing test, watch it fail for the reason you expect,
then make it pass. A test that has never failed has not been shown to test
anything.

Test output must be pristine — warnings in a passing run are a defect, not
noise to scroll past.
