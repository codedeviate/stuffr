#!/bin/sh
# Re-record the terminal fixtures from XZ Utils 5.8.4 (see README.md).
#
#   sh record.sh [/path/to/xz-5.8.4/bin]
#
# Each command runs under script(1), so standard error is a terminal, with
# `stty -onlcr` so that the terminal leaves every byte as xz wrote it. The
# leading "^D\b\b" script prints for its own empty standard input is cut.
# The inputs are made here, deterministically, in a scratch directory.
set -eu
bin=${1:-/opt/homebrew/opt/xz/bin}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1760 bytes: the line repeated 40 times (compresses to 132 bytes at -6).
i=0
while [ $i -lt 40 ]; do
	echo 'the quick brown fox jumps over the lazy dog'
	i=$((i + 1))
done > "$work/a"
cp "$work/a" "$work/b"
"$bin/xz" -c "$work/a" | head -c 100 > "$work/cut.xz"
# 20 MB of a fixed pseudo-random sequence: slow enough at -9e -T1 to be
# signalled mid-run.
awk 'BEGIN { srand(1); for (i = 0; i < 2500000; i++) printf "%08x", int(rand() * 4294967296) }' \
	> "$work/big"

rec() {
	out=$1
	shift
	LC_ALL=C script -q /dev/null sh -c "cd '$work' && stty -onlcr && PATH='$bin':\$PATH && { $*; }" \
		< /dev/null | perl -pe 's/^\^D\x08\x08// if $. == 1' > "$here/$out"
}

rec two_files.txt 'xz -v -k a b'
rec corrupt.txt 'xz -dv -k cut.xz'
rec stdin.txt 'xz -v < a > s.xz'
rec files.txt "printf 'a\nb\n' | xz -fkv --files"
# Timing-dependent values: only the shape is compared.
rec signals.txt 'xz -9e -T1 -c big > /dev/null & p=$!; sleep 0.5; kill -USR1 $p; sleep 0.3; kill -ALRM $p; wait $p'
