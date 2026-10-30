#!/bin/sh
# What `stuffr ls` identifies in a set of folders, counted.
#
#   identify-sweep.sh [--bin PATH] DIR...
#
# Runs `stuffr ls -r -a --json` on each DIR (default binary
# `target/release/stuffr`) and prints, per folder, a table of format x file
# extension counts, largest first, then the same table over every folder.
# Read-only: it reads what `stuffr ls` reads (at most the first 4096 and the
# last 512 bytes of a file) and writes only its own temporary folder, removed
# on exit. Used to compare identification against a recon of real folders
# (`~/Downloads`, `/Applications`, `/System/Library`): a false positive is a
# row whose extension does not belong to its format.
#
# `stuffr ls` exits 4 when something inside a folder is unreadable; that
# folder's table is still printed, with a note. Any other failure stops the
# sweep. Needs python3.

set -eu

usage() {
	echo "usage: identify-sweep.sh [--bin PATH] DIR..." >&2
	exit 2
}

bin=target/release/stuffr
while [ $# -gt 0 ]; do
	case $1 in
	--bin)
		[ $# -ge 2 ] || usage
		bin=$2
		shift 2
		;;
	--bin=*)
		bin=${1#--bin=}
		shift
		;;
	--)
		shift
		break
		;;
	-*) usage ;;
	*) break ;;
	esac
done
[ $# -gt 0 ] || usage
if [ ! -x "$bin" ]; then
	echo "identify-sweep: no stuffr binary at $bin (build it, or pass --bin)" >&2
	exit 2
fi
command -v python3 >/dev/null 2>&1 || {
	echo "identify-sweep: python3 is required" >&2
	exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/identify-sweep.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

n=0
for dir in "$@"; do
	n=$((n + 1))
	rc=0
	"$bin" ls -r -a --json "$dir" >"$work/$n.json" 2>"$work/$n.err" || rc=$?
	case $rc in
	0) ;;
	4) printf '%s\n' "$dir" >"$work/$n.partial" ;;
	*)
		echo "identify-sweep: stuffr ls $dir exited $rc:" >&2
		cat "$work/$n.err" >&2
		exit 1
		;;
	esac
	printf '%s\n' "$dir" >"$work/$n.dir"
done

python3 -I - "$work" "$n" <<'PY'
import json
import os
import sys
from collections import Counter

work, count = sys.argv[1], int(sys.argv[2])


def extension(path):
    name = os.path.basename(path)
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        return "(none)"
    return "." + ext.lower()


def table(title, counts):
    print(title)
    if not counts:
        print("  (nothing identified)")
        return
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    fw = max(len("FORMAT"), *(len(f) for (f, _), _ in rows))
    print(f"  {'COUNT':>7}  {'FORMAT':<{fw}}  EXT")
    for (fmt, ext), n in rows:
        print(f"  {n:>7}  {fmt:<{fw}}  {ext}")
    print(f"  {sum(counts.values()):>7}  files identified")


total = Counter()
for i in range(1, count + 1):
    with open(os.path.join(work, f"{i}.dir"), encoding="utf-8") as f:
        folder = f.read().rstrip("\n")
    with open(os.path.join(work, f"{i}.json"), encoding="utf-8") as f:
        listing = json.load(f)
    counts = Counter(
        (e["format"], extension(e["path"]))
        for e in listing["entries"]
        if e.get("kind") == "file" and e.get("format")
    )
    total.update(counts)
    table(folder, counts)
    if os.path.exists(os.path.join(work, f"{i}.partial")):
        print(f"  note: {len(listing.get('warnings', []))} unreadable inside (stuffr ls exited 4)")
    print()

table(f"TOTAL ({count} folder{'s' if count != 1 else ''})", total)
PY
