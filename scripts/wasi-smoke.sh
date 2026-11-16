#!/usr/bin/env bash
# Smoke test for the wasm32-wasip1 build of stuffr-cli, run under the wazero
# CLI. Usage: scripts/wasi-smoke.sh <stuffr.wasm>   (or `make wasi-smoke`)
#
# The runtime is the wazero v1.12.0 release binary (the version sercon
# embeds), downloaded once into target/wasi-smoke/ and checked against the
# SHA-256 pinned below on every run, cached or not. Needs curl and tar.
#
# Every check runs even when an earlier one fails. Each prints one line:
#   ok <name>                  passed
#   FAIL <name>: <detail>      failed, and is not in XFAIL
#   XFAIL <name>: <detail>     failed, and is listed in XFAIL
#   XPASS <name>               passed, but is listed in XFAIL
# The exit status is non-zero on any FAIL or XPASS: an XFAIL entry that
# starts passing must be removed, so the list cannot rot.
set -euo pipefail

# Checks expected to fail, each with its cause and the item that fixes it.
XFAIL=(
  # Item 10: wasm32-wasip1 cannot spawn a thread, so a pack asked for
  # workers exits 1 ("Not supported (os error 58)") instead of falling back
  # to one.
  pack-threads
  # Item 10: the xz personality's own worker handling, same cause (exit 1,
  # "Internal error (bug)").
  xz-personality-T8
)

WAZERO_VERSION=1.12.0
# From the release's own wazero_1.12.0_checksums.txt
# (https://github.com/tetratelabs/wazero/releases/tag/v1.12.0), which match
# the asset digests GitHub records for the release.
wazero_sha256() {
  case $1 in
    darwin_amd64) echo 4a142b30ab0c7cfeae3fb453c5d2f3beca5af823d5aeeb4c0de458f89e9d5bb8 ;;
    darwin_arm64) echo c9e811bb8638163a294de8579923a4ce759846dc04f964468855a23e69bbe73c ;;
    linux_amd64) echo 88019896950340e8839b94af0510b248c3400d8d8f4a9b335dcaad93ac0484ff ;;
    linux_arm64) echo b5e5105a8bc4817a117e52402713f0628ebe13ecec5c4e63d541c430ca9bf259 ;;
    *) return 1 ;;
  esac
}

wasm=$(realpath "${1:?usage: wasi-smoke.sh <stuffr.wasm>}")
root=$(dirname "$(dirname "$(realpath "$0")")")
cache=$root/target/wasi-smoke
mkdir -p "$cache"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/stuffr-wasi-smoke.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# --- the runtime -----------------------------------------------------------

case $(uname -s) in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) os=unknown ;;
esac
case $(uname -m) in
  arm64 | aarch64) arch=arm64 ;;
  x86_64 | amd64) arch=amd64 ;;
  *) arch=unknown ;;
esac
want=$(wazero_sha256 "${os}_${arch}") || {
  echo "FAIL setup: no pinned wazero checksum for $(uname -s)/$(uname -m)"
  exit 1
}
asset=wazero_${WAZERO_VERSION}_${os}_${arch}.tar.gz
tarball=$cache/$asset
if [ ! -f "$tarball" ]; then
  curl -fsSL --retry 3 -o "$tarball.part" \
    "https://github.com/tetratelabs/wazero/releases/download/v$WAZERO_VERSION/$asset"
  mv "$tarball.part" "$tarball"
fi
got=$(sha256 "$tarball")
if [ "$got" != "$want" ]; then
  echo "FAIL setup: $tarball has SHA-256 $got, want $want"
  rm -f "$tarball"
  exit 1
fi
mkdir -p "$tmp/bin"
tar -xzf "$tarball" -C "$tmp/bin" wazero
wazero=$tmp/bin/wazero

# --- the guest -------------------------------------------------------------

# The guest sees the scratch folder $w as /w. wazero's compiled code is
# cached next to the tarball (keyed by wazero's version and the module).
w=$tmp/w
out=$tmp/out
err=$tmp/err
mkdir -p "$w" "$tmp/argv0"
rc=0

# run <module> <args...>: one guest run; sets rc, stdout in $out, stderr in
# $err. The wazero CLI sets argv[0] to the module file's basename, so a copy
# of the module named `gzip` or `xz` selects that personality.
run() {
  local module=$1
  shift
  rc=0
  "$wazero" run -cachedir "$cache/compiled" -mount="$w:/w" \
    -env=STUFFR_CWD=/w -env=NO_COLOR=1 -env=TERM=dumb \
    "$module" "$@" <"/dev/null" >"$out" 2>"$err" || rc=$?
}
stuffr() { run "$wasm" "$@"; }
personality() {
  local name=$1
  shift
  [ -f "$tmp/argv0/$name" ] || cp "$wasm" "$tmp/argv0/$name"
  run "$tmp/argv0/$name" "$@"
}

# A trap is the guest dying on a wasm runtime error (`unreachable`, which is
# what a Rust panic or a failed allocation becomes under panic=abort) instead
# of calling proc_exit. The wazero CLI handles the two differently
# (cmd/wazero/wazero.go, doRun): a proc_exit surfaces as sys.ExitError and
# becomes the process's exit status verbatim, with nothing added to stderr;
# any other error, a trap included, is printed as
# `error instantiating wasm binary: <err>` (the wasm stack trace follows)
# and the CLI exits 1. So a trap is exit 1 AND that line on stderr. stuffr
# never prints that line itself, and its own exit 1 carries no such line.
trapped() {
  [ "$rc" -eq 1 ] && grep -q '^error instantiating wasm binary: ' "$err"
}

# The trap's runtime error, a panic message, or the last stderr line: the
# detail a FAIL prints.
why() {
  local line
  line=$(grep -m1 -E '^error instantiating wasm binary: |panicked' "$err" || tail -n 1 "$err" || true)
  printf 'exit %s: %s' "$rc" "$(printf '%s' "$line" | cut -c1-240)"
}

# expect_exit <code>: the last run exited <code> by proc_exit.
detail=
expect_exit() {
  if trapped; then
    detail="trapped, want exit $1: $(why)"
    return 1
  fi
  if [ "$rc" -ne "$1" ]; then
    detail="want exit $1, got $(why)"
    return 1
  fi
}

fails=0
xpasses=0
xfails=0
passes=0
is_xfail() {
  local x
  # The `+` form: an empty list is unbound to bash 3.2 under `set -u`.
  for x in ${XFAIL[@]+"${XFAIL[@]}"}; do
    [ "$x" = "$1" ] && return 0
  done
  return 1
}
# check <name> <function>: run one check and report it.
check() {
  local name=$1
  detail=
  if "$2"; then
    if is_xfail "$name"; then
      echo "XPASS $name"
      xpasses=$((xpasses + 1))
    else
      echo "ok $name"
      passes=$((passes + 1))
    fi
  elif is_xfail "$name"; then
    echo "XFAIL $name: $detail"
    xfails=$((xfails + 1))
  else
    echo "FAIL $name: $detail"
    fails=$((fails + 1))
  fi
}

# --- fixtures --------------------------------------------------------------

mkdir -p "$w/tree/sub"
printf 'hello wasi\n' >"$w/tree/a.txt"
printf 'nested content\n' >"$w/tree/sub/b.txt"
# ~2 MiB of compressible but non-trivial text: the payload of the codec and
# personality checks.
awk 'BEGIN { for (i = 0; i < 60000; i++) printf "line %d of the smoke payload %x\n", i, i * 2654435761 % 4294967296 }' \
  >"$w/tree/big.txt"
cp "$w/tree/big.txt" "$w/p.txt"
cp "$w/tree/big.txt" "$w/x.txt"

# A zstd frame whose window descriptor declares 1 GiB (0xa0: exponent 20,
# windowLog 30), holding one 4-byte raw block "abcd". The reference zstd
# 1.5.7 decodes it with --memory=1024MB and refuses it without.
printf '%b' '\x28\xb5\x2f\xfd\x00\xa0\x21\x00\x00abcd' >"$w/window-1g.zst"
# An xz stream (CRC32 check) with one LZMA2 block whose dictionary property
# is 0x24 (1 GiB), holding one uncompressed chunk "abcd". `xz -lvv` reports
# `--lzma2=dict=1GiB`, "Memory needed: 1025 MiB", and `xz -dc` decodes it.
printf '%b' '\xfd\x37\x7a\x58\x5a\x00\x00\x01\x69\x22\xde\x36' \
  '\x02\x00\x21\x01\x24\x00\x00\x00\x5e\x1f\xc7\xf9' \
  '\x01\x00\x03\x61\x62\x63\x64\x00\x11\xcd\x82\xed' \
  '\x00\x01\x18\x04\x6b\xe9\xf0\xa5\x90\x42\x99\x0d' \
  '\x01\x00\x00\x00\x00\x01\x59\x5a' >"$w/dict-1g.xz"

# --- checks ----------------------------------------------------------------

c_formats() {
  stuffr formats
  expect_exit 0 || return 1
  grep -q gzip "$out" || {
    detail="no gzip in the formats table"
    return 1
  }
}

# The last run's stdout, kept in the guest's folder as <name>.
keep() { cp "$out" "$w/$1"; }

# list then unpack /w/<archive>, compared file for file with the source tree.
list_and_unpack() {
  local archive=$1 into=$2
  stuffr list "/w/$archive"
  expect_exit 0 || {
    detail="list: $detail"
    return 1
  }
  grep -q 'tree/a.txt' "$out" && grep -q 'tree/sub/b.txt' "$out" || {
    detail="list does not name tree/a.txt and tree/sub/b.txt"
    return 1
  }
  stuffr unpack -C "/w/$into" "/w/$archive"
  expect_exit 0 || {
    detail="unpack: $detail"
    return 1
  }
  diff -r "$w/tree" "$w/$into/tree" >/dev/null 2>&1 || {
    detail="unpacked tree differs from the source"
    return 1
  }
}

# The user's path: pack to a named file, then list and unpack it.
c_roundtrip() {
  stuffr pack -o /w/t.tar.gz /w/tree
  expect_exit 0 || {
    detail="pack: $detail"
    return 1
  }
  list_and_unpack t.tar.gz out
}

# The same round trip with the archive written to stdout, which never takes
# the named-output path `roundtrip` exercises; the hostile fixtures below are
# made this way too, so they test the readers whatever that path does.
c_roundtrip_stdout() {
  stuffr pack --format tar -o - /w/tree
  expect_exit 0 || {
    detail="pack -o -: $detail"
    return 1
  }
  keep s.tar
  list_and_unpack s.tar out-stdout
}

# Worker threads, to stdout so a failure here is about the threads alone.
c_pack_threads() {
  stuffr pack --threads 8 --format xz -o - /w/tree/big.txt
  expect_exit 0 || {
    detail="pack --threads 8: $detail"
    return 1
  }
  keep big8.xz
  stuffr cat /w/big8.xz
  expect_exit 0 || {
    detail="cat: $detail"
    return 1
  }
  cmp -s "$out" "$w/tree/big.txt" || {
    detail="cat output differs from the input"
    return 1
  }
}

c_gzip_personality() {
  personality gzip -k /w/p.txt
  expect_exit 0 || {
    detail="gzip -k: $detail"
    return 1
  }
  personality gzip -dc /w/p.txt.gz
  expect_exit 0 || {
    detail="gzip -dc: $detail"
    return 1
  }
  cmp -s "$out" "$w/p.txt" || {
    detail="gzip -dc output differs from the input"
    return 1
  }
}

# xz_personality <name> <compress args...>: compress /w/x.txt with the xz
# personality, decompress the result with `xz -dc`, and compare. Without -c
# the output is /w/x.txt.xz; with it, stdout.
xz_roundtrip() {
  personality xz "$@" /w/x.txt
  expect_exit 0 || {
    detail="xz $*: $detail"
    return 1
  }
  case " $* " in *" -c "*) keep x.txt.xz ;; esac
  personality xz -dc /w/x.txt.xz
  expect_exit 0 || {
    detail="xz -dc: $detail"
    return 1
  }
  cmp -s "$out" "$w/x.txt" || {
    detail="xz -dc output differs from the input"
    return 1
  }
}
# To stdout, so a failure here is about the threads alone.
c_xz_personality_t8() { xz_roundtrip -T8 -c; }
# One thread, to a named file: the personality's own output path.
c_xz_personality_file() { xz_roundtrip -T1 -k; }

# A relative path, resolved against STUFFR_CWD=/w (the archive
# roundtrip-stdout kept).
c_list_relative() {
  stuffr list s.tar
  expect_exit 0 || return 1
  grep -q 'tree/a.txt' "$out" || {
    detail="list does not name tree/a.txt"
    return 1
  }
}

# Hostile input: `test` on a damaged archive must exit 5 (corrupt), by
# proc_exit, not by trapping.
hostile() {
  stuffr test "/w/hostile/$1"
  expect_exit 5
}
# Containers stuffr writes: pack the tree (to stdout), keep the first half of
# the bytes, so big.txt's payload, or zip's central directory, is cut short.
truncated() {
  local format=$1
  stuffr pack --format "$format" -o - /w/tree
  expect_exit 0 || {
    detail="pack --format $format: $detail"
    return 1
  }
  local size
  size=$(wc -c <"$out")
  head -c $((size / 2)) "$out" >"$w/hostile/truncated.$format"
  hostile "truncated.$format"
}
c_hostile_tar() { truncated tar; }
c_hostile_ar() { truncated ar; }
c_hostile_cpio() { truncated cpio; }
c_hostile_zip() { truncated zip; }
c_hostile_lha() { truncated lha; }
c_hostile_arj() { truncated arj; }
# Containers stuffr only reads: the corpus's own CRC-16-mismatch fixtures.
c_hostile_arc() { hostile wrongcrc16.arc; }
c_hostile_zoo() { hostile wrongcrc16.zoo; }

# Memory exhaustion: a header declaring 1 GiB, under the default memory
# limit (the 256 MiB floor on WASI), must exit 6 (limit) before allocating.
c_limit_zstd() {
  stuffr test /w/window-1g.zst
  expect_exit 6
}
c_limit_xz() {
  stuffr test /w/dict-1g.xz
  expect_exit 6
}

mkdir -p "$w/hostile"
legacy=$root/crates/stuffr-formats/fixtures/legacy
cp "$legacy/arc/wrongcrc16.arc" "$legacy/zoo/wrongcrc16.zoo" "$w/hostile/"

# The detector itself, against this wazero: a module whose _start is one
# `unreachable` must count as a trap.
c_trap_detector() {
  printf '%b' '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00' \
    '\x03\x02\x01\x00\x07\x0a\x01\x06_start\x00\x00\x0a\x05\x01\x03\x00\x00\x0b' \
    >"$tmp/unreachable.wasm"
  run "$tmp/unreachable.wasm"
  trapped || {
    detail="a module that executes unreachable was not detected as a trap: $(why)"
    return 1
  }
}

check trap-detector c_trap_detector
check formats c_formats
check roundtrip c_roundtrip
check roundtrip-stdout c_roundtrip_stdout
check pack-threads c_pack_threads
check gzip-personality c_gzip_personality
check list-relative c_list_relative
check hostile-tar c_hostile_tar
check hostile-ar c_hostile_ar
check hostile-cpio c_hostile_cpio
check hostile-zip c_hostile_zip
check hostile-lha c_hostile_lha
check hostile-arj c_hostile_arj
check hostile-arc c_hostile_arc
check hostile-zoo c_hostile_zoo
check limit-zstd c_limit_zstd
check limit-xz c_limit_xz
check xz-personality-T8 c_xz_personality_t8
check xz-personality-file c_xz_personality_file

echo "$passes ok, $xfails xfail, $fails fail, $xpasses xpass"
[ "$fails" -eq 0 ] && [ "$xpasses" -eq 0 ]
