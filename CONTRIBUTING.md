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

### What the gate costs, and the trap in the answer

**Two regimes, and the slow one is not this project's code.**

- **~5 minutes when nothing was relinked.** Measured on an Apple Silicon Mac
  at Salvage Stage 2 Task 8: **289 s** total — `fmt-check` 1 s, `lint` 1 s,
  `test` (`--all-features`) 112 s, `test-pure` 175 s, `release` 0 s.
  Real test EXECUTION inside that is only **29.8 s** and **42.2 s** per leg
  (summed from libtest's own `finished in` figures); the rest is cargo's own
  work, doc-test compilation most visibly.
- **20-40 minutes on the first gate after anything relinked**, including the
  first gate of a session, after a dependency or feature change, and always
  after `cargo clean`.

**The difference is macOS evaluating every newly-linked unsigned binary the
first time it is executed** — `/usr/libexec/syspolicyd`, Gatekeeper's policy
daemon, observed at 27-70% CPU throughout. `cargo test` links ~24 test
binaries per leg and each pays it once. Three measurements, all with `--list`
so that libtest runs no tests at all:

| what | wall clock |
|---|---|
| first execution of a newly-linked test binary | **164.86 s** |
| second execution of that same binary | **0.05 s** |
| a byte-identical COPY of it, at a new path | **81.59 s** |

The cost follows the FILE, not the code: the same file never pays twice, a
fresh copy pays again. That is the signature of first-execution
notarisation/Gatekeeper evaluation, and it is why a 41-minute gate and a
5-minute gate can both be healthy.

**The actionable part: do NOT `cargo clean` to "fix" a slow gate.** That is
the one action guaranteed to buy the expensive regime, and an implementer who
reads a stale "the gate takes under a minute" somewhere will reach for it.
Re-run the gate instead; with nothing changed it drops straight back to ~5
minutes.

For the record, the slowest actual TEST is
`lzma_pure::tests::corruption_sweep_is_detected_almost_everywhere` at
**19.17 s** — 91% of the slowest binary's wall time on the `--all-features`
leg. That cost is deliberate and documented (an exhaustive 128-byte sweep
over a pure-Rust codec in an unoptimised profile); it is not the thing to
chase.

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
| `0.6.0` | Salvage Stage 2 — four more salvage scanners (`arc`, `zoo`, `lha`, `arj`, joining `zip`), dispatch by resolved archive format, the shared `stream_verify` both CRC widths go through, and the per-entry write seam that came with them. A MINOR, not a `0.5.x` patch: `0.5.0` is PUBLISHED (crates.io, 2026-09-17) and Stage 2 breaks its `stuffr-core::salvage` API — `collect_candidates`/`annotate_candidates` both change signature, `UnverifiedCause` and `SalvageDisposition` both gain variants, `PartialCause::Truncated` is NARROWED and `DecodeFailed` added beside it, and `Candidate`/`SalvagedEntry`/`SalvageOutcome` are closed with `#[non_exhaustive]` plus constructors. Cargo reads a `0.x` middle number as the major, so a break to a published `0.5.0` cannot ship as `0.5.x`. The final fix wave adds to that set: `SalvageDisposition` gains a further variant (`SkippedUnsafePath` — a containment refusal is a per-entry outcome now, not a run abort), `SalvageScan` gains a `write_payload` method (defaulted, so additive for an implementor), `stuffr-formats::salvage_verify` becomes a `pub mod` so `stream_verify` is reachable at all, and `safe_join`/`check_symlink_target` refuse a NUL-bearing name at exit 7 where it used to reach the filesystem and exit 1. |
| `0.7.x`/later | Salvage Stage 3 (`tar`, `cpio`, `ar` — the three where a false positive is undetectable by construction, and the only place a `Complete` tier is genuinely reachable) and Phase 5 — compatibility symlinks, `convert`, polish. Not yet claimed by a single number; whichever lands next takes the next open one. |
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
Phase 5's original content moves to a later, not-yet-numbered row,
alongside whichever later Salvage stage lands next (a `Complete` tier
genuinely exercised by tar/cpio/ar, per the design's own Stage 3 — Stage 1
never exercises it, since zip always carries a CRC-32). Neither has landed,
so pinning either to an exact number now would be the same mistake that
moved `0.4.0`'s row twice already: claiming a number before the work behind
it is real.

The table was revised a **fifth** time, during Salvage Stage 2 Task 3c's
fix round 4, and the reason is worth keeping because it is a repeat: the
row for the remaining salvage stages said `0.5.x`, which was written while
`CLAUDE.md` still claimed `0.5.0` was "bumped but NOT tagged and NOT
published". It is published — crates.io, `2026-09-17T06:13:43Z`, tag
`v0.5.0` at `498a59f`, measured against the registry rather than against
either file — and Stage 2 breaks its published `stuffr-core::salvage` API,
so the next release is `0.6.0`. **Check crates.io, never a sentence in this
repository**: this is the second versioning argument a stale in-repo
publication claim has misled (see `CLAUDE.md`'s Ruling P for the first).

**The `0.6.0` row then LANDED rather than being revised**, and that
distinction is worth stating because every entry above it is a revision.
The row was written ahead of the work, as a claim about what Stage 2 would
break; when Stage 2 shipped it broke MORE than the row predicted
(`PartialCause::Truncated` narrowed and `DecodeFailed` added beside it in
`36c964d`, and two further `!`-marked commits, `5b57cb9` and `0a98c45`,
reshaping the same `stuffr-core::salvage` surface), so the row was widened
to say what actually shipped — the same treatment `0.3.0`'s row got, for the
same reason, and not a renumbering. The number it predicted was already
right, and was re-argued from the diff rather than inherited: see
`CLAUDE.md`'s Versioning section for that argument and for the dated
reverse-dependency measurement behind it. The `0.5.x`/later row moved on to
`0.7.x`, since `0.6.0` is now spent.

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

### The third shape: constructed downstream, through OUR constructor

The rule above has two answers — open (downstream constructs) and closed
(downstream only destructures) — and Salvage needed a third, because
`stuffr-core::salvage`'s `Candidate` is a struct downstream MUST construct
and MUST NOT be broken by a new field. `SalvageScan::next_candidate` returns
`Result<Option<Candidate>>`, so every out-of-crate scanner builds one; five
do inside this workspace and, since `0.5.0` is published, an external one is
no longer hypothetical. Under the open rule, each field Stage 2 added broke
all of them at once.

`#[non_exhaustive]` **alone** would have been the wrong fix, for exactly the
reason the capability structs stay open: it forbids `..` construction from
another crate, and `..Default::default()` is what an implementor would have
reached for. It only works **paired with a constructor the defining crate
owns** — the `ExpectedEntry::new`/`with_crc` shape, scaled up. So
`Candidate` carries `#[non_exhaustive]` plus `Candidate::new(offset,
payload_start, meta)` and four `with_*` setters, `SalvagedEntry` carries
`SalvagedEntry::new(..)` plus three, and `SalvageOutcome` carries the
attribute with no constructor at all (nothing outside this crate builds
one — `salvage_all` does).

**That is why the change waited.** It was raised as Ruling S-I in Stage 2
Task 1 and deliberately deferred to Task 9: designing a constructor for a
trait's return type from ONE caller guesses at the shape, and four more
scanners (`arc`, `zoo`, `lha`, `arj`) were due to land. All five now read
through it, with whichever fields a scanner does not set defaulting to the
answers that assert the least (no declared length, nothing to verify with,
nothing missing, nothing deleted).

**And the extension point protected here has to actually be reachable, or
the whole argument is spent on nothing.** The final whole-branch review
found it was not: `Verifier` was public and the only thing that turns one
plus a reader into a `SalvageStatus` — `salvage_verify::stream_verify` —
was `pub(crate)` in a **private** module, so an out-of-tree scanner had to
reimplement a streaming CRC-16/ARC and CRC-32 comparison to reach the
statuses `SalvageStatus` describes. That module is `pub` now, and
`SalvageScan` carries a defaulted `write_payload` so a scanner's write half
is declared beside its scan half rather than living only in the ops layer's
private dispatch. `crates/stuffr-formats/tests/salvage_seam.rs` implements a
sixth scanner from the published surface alone — an INTEGRATION test, so
everything it touches has to be genuinely `pub`.

**One half is still open and is Stage 3's, stated here rather than left
implied:** `stuffr salvage` resolves a format NAME to a scanner, with no
registration point a third party can add itself to, so an out-of-tree
scanner reaches `salvage_all` and none of `.partial` naming, `NAME.salvaged-N`
disambiguation, containment or `salvage_exit_code`. Closing that means a
salvage registry.

**The opposite call, on the same day, for `stuffr::entries::PartialCause`:
it stays OPEN, deliberately.** It is an enum, so "enums carry it" would seem
to settle it — but `stuffr-cli` matches it exhaustively to render each cause
as its own words (`Partial (truncated)`, `Partial (decode failed)`, `Partial
(checksum mismatch)`), and that is the whole reason the enum exists.
`#[non_exhaustive]` would force a wildcard arm there, and a future variant
would then print another cause's words with nothing failing to say so —
turning a compile error into a wrong sentence on a user's terminal. That is
the same trade as `Rung` and `StreamPolicy` in the section below: a closed
domain where an exhaustive `match` downstream is the point rather than the
hazard. `36c964d` added a variant to it in this very release and paid the
breaking change knowingly.

### Which enums are open, which are closed

"Enums carry it" above is not quite universal either. This paragraph said
"four public enums" until Salvage Stage 2's own release measured it; the
figure is **fourteen**, across `stuffr-core` and the facade, and the command
that answers it is worth keeping because the sentence went stale once
already:

```bash
find crates/stuffr-core/src crates/stuffr/src -name '*.rs' | sort | while read f; do
  awk -v F="$f" '/^#\[non_exhaustive\]/{ne=1}
                 /^pub enum /{printf "%s %s %s\n", (ne?"CLOSED":"OPEN"), F, $3}
                 /^pub (struct|enum|fn)/{ne=0}' "$f"
done | grep OPEN
```

(It reads only the two crates whose types other crates consume, and only
top-level `pub enum`s, which is where the question arises. `find` rather
than a `src/*.rs` glob: `SpillPolicy` lives in `src/source/spill.rs`, and a
flat glob misses it — which is how the old count was short by more than the
salvage enums alone.) The distinction
is whether the enum names an open-ended set that formats will keep adding
to, or a closed domain fixed by the crate's own design:

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
  - `PartialCause`, `SalvageStatus`, `UnverifiedCause`, `SalvageDisposition`,
    `PartialPolicy`, `Verifier` — the salvage vocabulary, and the same
    reasoning as `StreamPolicy` one bullet up, sharpened by what `stuffr-cli`
    does with them. It renders each one as its OWN words on a `salvage
    --list` row, so an exhaustive `match` is how a new cause is guaranteed
    to arrive with a sentence rather than inheriting a neighbour's under a
    wildcard. `36c964d` added `PartialCause::DecodeFailed` in `0.6.0` and
    paid the breaking change knowingly; see "The third shape" above for the
    full argument, and for the opposite call made the same day on
    `Candidate`.
  - `CorruptionDetection`, `Selection`, `Input`, `Output` — closed for the
    same reason: each is a fixed set the crate's own design fixes, and each
    is matched exhaustively by a consumer that must handle every arm.

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
| `salvage.rs` | Added in Salvage Stage 1 Task 8, pinned to `zip` until Salvage Stage 2 Task 3b. The one target that treats the REST of its bytes as a damaged ARCHIVE rather than as content fed to a decoder or container reader: it spools that payload to a real tempfile (salvage needs genuine random access) and calls the same `entries::salvage` path the CLI does. **Which format's scanner gets it is decided by the PAYLOAD'S OWN MAGIC where there is one** (Stage 2 Task 8, Ruling S-S — `slot_from_payload` runs the same `resolve_chain` a real `stuffr salvage ARCHIVE` runs), and by a leading selector byte over [`SALVAGE_SLOTS`](#the-slot-tables-are-append-only) — `zip`, `arc`, `zoo`, `lha`, `arj` — for everything else. **`dest` is a real directory** (Stage 2 Task 8, Ruling S-O), so the filesystem write path is in the oracle's view; it said `dest: None` until then, and that gap is why a 404-character entry name made `salvage -C` exit 1 mid-run and survived a whole stage. `SalvagePolicy::max_entry` is narrowed to `stuffr_core::testing::SALVAGE_FUZZ_MAX_ENTRY` (256 KiB) for the same reason: with a `dest` every ceiling is a disk bound. That constant lives in `stuffr-core` rather than in the target, because `fuzz/` is excluded from the workspace and a ceiling only the target can see is a ceiling no test can check a seed against — `every_salvage_seed_is_scanned_the_way_the_fuzz_target_scans_it` now runs the engine with the target's exact configuration and asserts both halves (every seed places a file; no seed's entry is over the ceiling). Seeded from eighteen shapes (`SALVAGE_SHAPES` in `crates/stuffr/tests/fuzz_corpus.rs`), at least one per slot — six hand-built zips (healthy, two duplicate-name shapes, a zeroed central directory, a truncated tail, a flipped payload byte) plus three each of ARC and LHA, four of ARJ and two of ZOO — every slot but ZOO now has a checksum-corrupted shape, and that one exception is a property of the borrowed fixtures (all four hold a single entry), stated in `SALVAGE_SHAPES`'s own doc. It ran **unseeded** until the Salvage Stage 1 final fix wave, and that was not a budget problem — see "Corpus and running locally" below for the measurement. |

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

`CODEC_SLOTS`, `CONTAINER_SLOTS` and, since Salvage Stage 2 Task 3b,
`SALVAGE_SLOTS` (`stuffr-core`'s `testing` module) map a fuzz input's
selector byte to a format name. **Append only — never reorder, never
remove; retire a slot by leaving it in place.** The ordering is the wire
format of every corpus seed on disk: a seed minimised against `bzip2`
is a seed whose selector byte, modulo the table's length, happens to land on
`bzip2`'s current index. Reorder the table and that same seed silently
starts feeding a different codec — nothing fails to tell you, and a corpus
built to cover twelve codecs quietly stops covering one of them.
`SALVAGE_SLOTS` lists only formats `entries::salvage_scan` actually
dispatches to a real scanner (`zip`, `arc`, `zoo`, `lha`, `arj`), never a
format merely registered as an ordinary container — see that constant's own
doc. Two tests in `crates/stuffr/tests/fuzz_corpus.rs` keep the table and the
corpus in step: `every_salvage_slot_carries_at_least_one_seed` fails the
build for a slot nobody wrote a seed shape for, and
`every_salvage_seed_is_recognised_as_the_slot_its_shape_names` fails for a
seed whose own bytes do not detect as the format its shape claims — which is
what `salvage.rs`'s magic-first routing depends on. A third,
`every_salvage_seed_is_scanned_the_way_the_fuzz_target_scans_it`, is the only
thing in `make check` that runs the engine with the target's OWN
configuration (a real destination and `SALVAGE_FUZZ_MAX_ENTRY`) rather than
the report-only one.

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

**The `salvage` target reports its own oracle-call count, on request.** Three
tasks in a row have had to measure "is the oracle actually firing?" by
hand-patching `salvage.rs`, taking a number, and reverting the patch — which
leaves the figure in a report and no way to reproduce it. It is now a
property of the harness, gated on an environment variable so an ordinary run
is unchanged:

```bash
STUFFR_FUZZ_SALVAGE_TRACE=1 cargo +nightly fuzz run salvage -- -runs=0 2>&1 \
  | grep '^salvage-trace '
```

`-runs=0` still executes every corpus file exactly once, so the output is one
line per input: the slot it reached, whether its own magic or its selector
byte chose that slot (`routed=magic` / `routed=selector`), how many rows the
scan produced, how many reached `Intact`, how many times
`check_salvage_claim` was actually called, and how many `Intact` rows the
target's raw-byte cross-check could not reach a verdict on. **`intact` and
`oracle` are different numbers and conflating them is the error two
consecutive tasks each made once**: the oracle call is skipped when the
independent second scan did not report that scan position, and when the
cross-check is inconclusive.

**Per-slot oracle counts vary by an order of magnitude between runs, so do
not read one run's table as a ranking.** Measured at Stage 2 Task 8, three
independent 100,000-run sessions each grown from the same fifteen seeds
(`-runs=100000`, `-seed=1` and `-seed=2`), then traced with `-runs=0` — total
`check_salvage_claim` calls per slot, `zip/arc/zoo/lha/arj`: selector-only
routing `3501/71/2/5/119`; magic-first routing `3902/83/25/6/11` and
`6000/138/2/8/30`. The `zoo` slot Ruling S-S was raised about reaches the
oracle on both, which Task 4's `876 inputs, 0 records` did not — and running
the magic-first binary over the selector-grown corpus reproduces that
corpus's own per-slot table almost exactly (`661/225/68/83/96` inputs against
`663/225/68/80/97`), with 1,023 of its 1,133 inputs — 90% — routed by magic
rather than by their selector byte (`zoo` the outlier at 38%). **libFuzzer's
coverage feedback was already doing most of the work the selector byte was
blamed for**: an input whose selector sent it to a scanner that finds nothing
produces no new coverage and is not kept. What the magic-first routing buys
is therefore not a measured coverage win — it is that a seeded archive
reaches its own scanner by construction rather than by that feedback
happening to preserve one byte, which is a guarantee the corpus generator's
own tests can then pin.

**`arj` is structurally last, and no amount of seeding moves it.** Read the
table above and the temptation is to chase `arj … 11` beside `zip … 3902`;
do not. `legacy/arj_salvage.rs`'s candidate gate requires every basic header
to reproduce a CRC-32 over its own content, so a mutation landing in a header
is rejected with probability ~1 − 2⁻³² — and the mutations that DO survive
are the ones in the payload, which that CRC does not cover, so they break the
entry's own file CRC-32 and yield `Partial`. `check_salvage_claim` fires on
`Intact` alone. **11-30 oracle calls is therefore the ceiling for that slot,
not a seeding gap**, and the two formats with the weakest anchors behave the
opposite way for the same structural reason: ARC's two-byte anchor makes
almost any bytes produce candidates, which is why a session seeded with
nothing but ARJ archives ended up 650 of its 782 accumulated inputs on the
`arc` slot.

**Two things this harness does not measure, named so the next reader does not
assume otherwise.** First, **how often mutation reaches a given decoder**:
`arj-method4-payload` exists to make `unarj-rs`'s `decode_fastest` reachable
behind a header that keeps parsing (measured live — `stuffr list` on the seed
answers `Invalid back_ptr` at exit 5), and nothing counts arrivals there or
anywhere else; a decoder can be reachable and starved at once and no figure
in this section would say so. Second, **the corpus's composition after a
session is not a coverage statement**: an input is kept because it produced
new coverage somewhere, which need not be in the slot its selector or its
magic names.

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
**on every `v*` tag**, weekly, and on demand via
`.github/workflows/fuzz-deep.yml`, independent of `ci.yml`.

**A tag's deep run must be green before anything is published from it**, and
that rule was bought rather than assumed. `v0.6.0` was tagged after a clean
`make check`, a green CI run, and a whole-branch review carrying an
independent 31,460-invocation corruption sweep. A deep run dispatched by hand
against that tag then found **four CLI-reachable defects in five rounds** — a
panic (exit 101 on a 602-byte `.Z` file) and two separate exit-1 classes —
and **none of them was reachable by `make check` or by the smoke fuzz here**.
Each was hidden behind the previous one, because libFuzzer aborts on its
first crash, so every fix opened ground the fuzzer had never reached.
`v0.6.0` was never published; `v0.6.1` carries the fixes. crates.io cannot be
unpublished, only yanked — a tag can simply be replaced, which is why the
gate sits there.

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
