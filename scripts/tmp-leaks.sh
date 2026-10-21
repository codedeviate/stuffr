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

NL='
'

# Fails (exit 2, with a message) when $1 exists but cannot be listed. A root
# that does not exist has nothing in it, which is fine.
require_listable_root() {
	if [ -e "$1" ] && { [ ! -d "$1" ] || [ ! -r "$1" ] || [ ! -x "$1" ]; }; then
		echo "tmp-leaks: temp root is not a readable directory: $1" >&2
		exit 2
	fi
}

# Names of the stuffr-* entries directly in $1, one per line. Names containing
# a newline are skipped everywhere (listed, checked, swept): a path list split
# on newlines would turn them into paths outside the root.
list_names() {
	find "$1" -mindepth 1 -maxdepth 1 -name 'stuffr-*' ! -name "*${NL}*" \
		-exec sh -c 'for p; do basename "$p"; done' sh {} + 2>/dev/null | sort
}

# Prints the pid embedded in name $1 (its first all-digit field after
# `stuffr-`), or nothing. Pids below 2 (0 and 1 always answer kill -0) are not
# pids. Parsed with parameter expansion, so nothing is globbed.
name_pid() {
	rest=${1#stuffr-}
	while [ -n "$rest" ]; do
		f=${rest%%-*}
		case $f in
		'' | *[!0-9]*) ;;
		*)
			if [ "$f" -lt 2 ] 2>/dev/null; then return; fi
			printf '%s\n' "$f"
			return
			;;
		esac
		if [ "$rest" = "$f" ]; then rest=; else rest=${rest#*-}; fi
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
	root=$(tmp_root)
	require_listable_root "$root"
	mkdir -p "$(dirname "$1")"
	list_names "$root" >"$1"
}

cmd_check() {
	[ $# -eq 1 ] || { echo 'usage: tmp-leaks.sh check FILE' >&2; exit 2; }
	[ -f "$1" ] || { echo "tmp-leaks: no snapshot at $1" >&2; exit 2; }
	root=$(tmp_root)
	require_listable_root "$root"
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
	[ -e "$root" ] || exit 0
	require_listable_root "$root"
	swept=0
	old=$(find "$root" -mindepth 1 -maxdepth 1 -name 'stuffr-*' ! -name "*${NL}*" -mtime +0 \
		-exec sh -c 'for p; do basename "$p"; done' sh {} + 2>/dev/null)
	while IFS= read -r n; do
		case $n in '' | */* | . | ..) continue ;; esac
		p=$root/$n
		name_is_live "$n" && continue
		if [ -L "$p" ]; then
			rm -f -- "$p" || continue
		else
			chmod -R u+rwX -- "$p" 2>/dev/null
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
	case $self in /*) ;; *) self=$PWD/$self ;; esac
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

	# --- hostile and awkward names ---
	# A newline name must not make sweep delete a sibling of the cwd.
	nl_work=$base/cwd
	mkdir -p "$nl_work/victim"
	echo v >"$nl_work/victim/f"
	nl_name="stuffr-x${NL}victim"
	mkdir "$root/$nl_name"
	touch -t "$stamp" "$root/$nl_name"
	mkdir "$root/stuffr-has space"
	touch -t "$stamp" "$root/stuffr-has space"
	out=$(cd "$nl_work" && sh "$self" sweep) || selftest_fail 'sweep with newline name failed'
	[ "$out" = 'swept 1 stale stuffr-* temp folders' ] || selftest_fail "sweep output with odd names: $out"
	[ -f "$nl_work/victim/f" ] || selftest_fail 'newline name made sweep delete outside the root'
	[ -d "$root/$nl_name" ] || selftest_fail 'newline-named entry was not skipped'
	[ ! -e "$root/stuffr-has space" ] || selftest_fail 'old name with a space survived'
	rmdir "$root/$nl_name"
	# pids 0 and 1 are not pids: not live, so a new such folder is a leak.
	mkdir "$root/stuffr-p0-0-1" "$root/stuffr-p1-1-1"
	out=$(sh "$self" check "$snap" 2>/dev/null) && selftest_fail 'check ignored pid 0/1 folders'
	case $out in
	*stuffr-p0-0-1*stuffr-p1-1-1* | *stuffr-p1-1-1*stuffr-p0-0-1*) ;;
	*) selftest_fail "check did not name both pid 0/1 folders: $out" ;;
	esac
	rmdir "$root/stuffr-p0-0-1" "$root/stuffr-p1-1-1"
	# A root path with a space, and an unreadable root.
	spaced="$base/root with space"
	mkdir "$spaced"
	STUFFR_TMP_ROOT=$spaced sh "$self" snapshot "$base/snap2" || selftest_fail 'snapshot in spaced root failed'
	mkdir "$spaced/stuffr-y-999999-1"
	out=$(STUFFR_TMP_ROOT=$spaced sh "$self" check "$base/snap2" 2>/dev/null)
	[ $? -eq 1 ] || selftest_fail 'check in spaced root did not exit 1'
	case $out in
	*"$spaced/stuffr-y-999999-1"*) ;;
	*) selftest_fail "spaced root leak not named: $out" ;;
	esac
	mkdir "$base/noaccess"
	chmod 000 "$base/noaccess"
	if [ ! -r "$base/noaccess" ]; then # skipped when running as root
		STUFFR_TMP_ROOT=$base/noaccess sh "$self" check "$snap" >/dev/null 2>&1
		[ $? -eq 2 ] || selftest_fail 'check passed on an unreadable root'
	fi
	chmod 755 "$base/noaccess"
	STUFFR_TMP_ROOT=$base/missing sh "$self" check "$snap" >/dev/null 2>&1 \
		|| selftest_fail 'check failed on a root that does not exist'
	echo 'tmp-leaks selftest passed'
}

case ${1:-} in
snapshot) shift; cmd_snapshot "$@" ;;
check) shift; cmd_check "$@" ;;
sweep) cmd_sweep ;;
selftest) cmd_selftest ;;
*) echo 'usage: tmp-leaks.sh snapshot FILE | check FILE | sweep | selftest' >&2; exit 2 ;;
esac
