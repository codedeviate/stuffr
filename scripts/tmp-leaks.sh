#!/bin/sh
# Leak detector and sweep for stuffr's `stuffr-*` temp folders.
#
#   tmp-leaks.sh snapshot FILE   record the current stuffr-* names in FILE
#   tmp-leaks.sh check FILE      list names not in FILE whose pid is not alive;
#                                exit 1 if there are any
#   tmp-leaks.sh sweep           remove stuffr-* entries older than one day
#   tmp-leaks.sh selftest        run all of the above in a fake temp dir
#
# Scope: only direct children of the user's temp directory named `stuffr-*`.
# `STUFFR_TMP_ROOT` replaces that directory and exists for the self-test only.
# Symlinks are never followed: a `stuffr-*` link is removed as a link.
#
# A name's pid is its first all-digit `-`-separated field after `stuffr-`
# (`stuffr-extract-<pid>-<n>`). A live pid means another run (a concurrent gate,
# an overnight fuzz) owns the folder, so neither `check` nor `sweep` touches it.
# A pid that exists but belongs to another user (EPERM) is alive too.

set -u

tmp_root() {
	if [ -n "${STUFFR_TMP_ROOT:-}" ]; then
		root=$STUFFR_TMP_ROOT
	elif [ "$(uname -s)" = Darwin ] && d=$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null) && [ -n "$d" ]; then
		root=$d
	else
		root=${TMPDIR:-/tmp}
	fi
	# Strip trailing slashes, but keep a bare "/".
	while [ "${root%/}" != "$root" ] && [ "$root" != / ]; do root=${root%/}; done
	printf '%s\n' "$root"
}

# Names of the stuffr-* entries directly in $1, one per line.
list_names() {
	find "$1" -maxdepth 1 -name 'stuffr-*' 2>/dev/null | while IFS= read -r p; do
		basename "$p"
	done | sort
}

# Prints the pid embedded in name $1, or nothing.
name_pid() {
	rest=${1#stuffr-}
	old_ifs=$IFS
	IFS=-
	# shellcheck disable=SC2086
	set -- $rest
	IFS=$old_ifs
	for f in "$@"; do
		case $f in
		'' | *[!0-9]*) ;;
		*)
			printf '%s\n' "$f"
			return
			;;
		esac
	done
}

# kill -0 fails with EPERM for another user's process; ps -p still sees it.
pid_alive() {
	kill -0 "$1" 2>/dev/null || ps -p "$1" >/dev/null 2>&1
}

name_is_live() {
	lp=$(name_pid "$1")
	[ -n "$lp" ] && pid_alive "$lp"
}

cmd_snapshot() {
	[ $# -eq 1 ] || { echo 'usage: tmp-leaks.sh snapshot FILE' >&2; exit 2; }
	mkdir -p "$(dirname "$1")"
	list_names "$(tmp_root)" >"$1"
}

cmd_check() {
	[ $# -eq 1 ] || { echo 'usage: tmp-leaks.sh check FILE' >&2; exit 2; }
	[ -f "$1" ] || { echo "tmp-leaks: no snapshot at $1" >&2; exit 2; }
	root=$(tmp_root)
	leaks=0
	names=$(list_names "$root")
	while IFS= read -r n; do
		[ -n "$n" ] || continue
		grep -Fxq -- "$n" "$1" && continue
		name_is_live "$n" && continue
		echo "leaked temp folder: $root/$n"
		leaks=$((leaks + 1))
	done <<EOF2
$names
EOF2
	if [ "$leaks" -gt 0 ]; then
		echo "tmp-leaks: $leaks stuffr-* temp folder(s) left behind by the tests" >&2
		exit 1
	fi
}

cmd_sweep() {
	root=$(tmp_root)
	[ -d "$root" ] || exit 0
	swept=0
	old=$(find "$root" -maxdepth 1 -name 'stuffr-*' -mtime +0 2>/dev/null)
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		name_is_live "$(basename "$p")" && continue
		if [ -L "$p" ]; then
			rm -f -- "$p" || continue
		else
			chmod -R u+rwx -- "$p" 2>/dev/null
			rm -rf -- "$p"
			[ -e "$p" ] && continue
		fi
		swept=$((swept + 1))
	done <<EOF2
$old
EOF2
	if [ "$swept" -gt 0 ]; then
		echo "swept $swept stale stuffr-* temp folders"
	fi
}

selftest_fail() {
	echo "tmp-leaks selftest FAILED: $1" >&2
	exit 1
}

# Sets $old_stamp to a touch -t stamp two days ago (BSD or GNU date).
two_days_ago() {
	date -v-2d +%Y%m%d%H%M 2>/dev/null || date -d '2 days ago' +%Y%m%d%H%M
}

cmd_selftest() {
	self=$0
	base=$(mktemp -d "${TMPDIR:-/tmp}/tmp-leaks-selftest.XXXXXX") || exit 1
	trap 'chmod -R u+rwx "$base" 2>/dev/null; rm -rf "$base"' EXIT INT TERM
	root=$base/root
	outside=$base/outside
	mkdir -p "$root" "$outside"
	echo precious >"$outside/keep.txt"
	stamp=$(two_days_ago)
	export STUFFR_TMP_ROOT=$root

	# --- sweep ---
	mkdir -p "$root/stuffr-test-old/ro" "$root/stuffr-test-new" "$root/other-old" \
		"$root/stuffr-live-$$-1" "$root/subdir/stuffr-nested-old"
	echo x >"$root/stuffr-test-old/ro/x"
	chmod 555 "$root/stuffr-test-old/ro"
	ln -s "$outside" "$root/stuffr-link-old"
	for p in "$root/stuffr-test-old" "$root/other-old" "$root/stuffr-live-$$-1" \
		"$root/subdir/stuffr-nested-old"; do
		touch -t "$stamp" "$p"
	done
	touch -h -t "$stamp" "$root/stuffr-link-old"
	out=$(sh "$self" sweep) || selftest_fail 'sweep exited non-zero'
	# Two are swept: the read-only tree and the symlink.
	[ "$out" = 'swept 2 stale stuffr-* temp folders' ] || selftest_fail "sweep output was: $out"
	[ ! -e "$root/stuffr-test-old" ] || selftest_fail 'old stuffr-test-old (with read-only subdir) survived'
	[ ! -L "$root/stuffr-link-old" ] || selftest_fail 'old stuffr-* symlink survived'
	[ -f "$outside/keep.txt" ] || selftest_fail 'symlink target was touched'
	[ -d "$root/stuffr-test-new" ] || selftest_fail 'fresh stuffr-test-new was swept'
	[ -d "$root/other-old" ] || selftest_fail 'non-stuffr other-old was swept'
	[ -d "$root/stuffr-live-$$-1" ] || selftest_fail 'old folder of a live pid was swept'
	[ -d "$root/subdir/stuffr-nested-old" ] || selftest_fail 'nested stuffr-* was swept'
	out=$(sh "$self" sweep) || selftest_fail 'second sweep exited non-zero'
	[ -z "$out" ] || selftest_fail "second sweep printed: $out"

	# --- snapshot / check ---
	snap=$base/snapshot
	sh "$self" snapshot "$snap" || selftest_fail 'snapshot failed'
	grep -Fxq stuffr-test-new "$snap" || selftest_fail 'snapshot misses stuffr-test-new'
	sh "$self" check "$snap" >/dev/null || selftest_fail 'check failed with nothing new'
	mkdir "$root/stuffr-x-$$-1"
	out=$(sh "$self" check "$snap") || selftest_fail "check reported a live-pid folder: $out"
	mkdir "$root/stuffr-x-999999-1"
	out=$(sh "$self" check "$snap" 2>/dev/null)
	rc=$?
	[ "$rc" -eq 1 ] || selftest_fail "check exit was $rc, expected 1"
	case $out in
	*stuffr-x-999999-1*) ;;
	*) selftest_fail "check did not name the dead-pid folder: $out" ;;
	esac
	case $out in
	*"stuffr-x-$$-1"*) selftest_fail 'check named the live-pid folder' ;;
	esac
	echo 'tmp-leaks selftest passed'
}

case ${1:-} in
snapshot) shift; cmd_snapshot "$@" ;;
check) shift; cmd_check "$@" ;;
sweep) cmd_sweep ;;
selftest) cmd_selftest ;;
*) echo 'usage: tmp-leaks.sh snapshot FILE | check FILE | sweep | selftest' >&2; exit 2 ;;
esac
