#!/bin/sh
# Exercise tools/install_plugin.sh without touching the real IDA directory.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
src="$root/plugin/rosetta.py"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rosetta-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

dest="$tmp/plugins/rosetta.py"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# 1. fresh install creates the symlink
sh "$root/tools/install_plugin.sh" "$src" "$dest" >/dev/null
[ -L "$dest" ] || fail "fresh install did not create a symlink"
[ "$(readlink "$dest")" = "$src" ] || fail "fresh install points elsewhere"
pass "fresh install"

# 2. repeat install is idempotent
sh "$root/tools/install_plugin.sh" "$src" "$dest" >/dev/null
[ -L "$dest" ] || fail "repeat install broke the symlink"
pass "idempotent install"

# 3. a regular file is not clobbered
rm -f "$dest"; echo "user copy" > "$dest"
if sh "$root/tools/install_plugin.sh" "$src" "$dest" >/dev/null 2>&1; then
    fail "install overwrote a regular file"
fi
[ -f "$dest" ] && [ ! -L "$dest" ] || fail "regular file was removed"
[ "$(cat "$dest")" = "user copy" ] || fail "regular file was modified"
pass "regular file protected"

# 4. FORCE backs it up, then links
sh "$root/tools/install_plugin.sh" "$src" "$dest" 1 >/dev/null
[ -L "$dest" ] || fail "FORCE did not create a symlink"
bak=$(ls "$dest".bak.* 2>/dev/null | head -1 || true)
[ -n "$bak" ] || fail "FORCE did not back up the file"
[ "$(cat "$bak")" = "user copy" ] || fail "backup content is wrong"
pass "FORCE backs up a regular file"

# 5. a foreign symlink is not clobbered
rm -f "$dest" "$dest".bak.*
other="$tmp/other.py"; echo "other" > "$other"
ln -s "$other" "$dest"
if sh "$root/tools/install_plugin.sh" "$src" "$dest" >/dev/null 2>&1; then
    fail "install overwrote a foreign symlink"
fi
[ "$(readlink "$dest")" = "$other" ] || fail "foreign symlink changed"
pass "foreign symlink protected"

# 6. FORCE replaces a foreign symlink
sh "$root/tools/install_plugin.sh" "$src" "$dest" 1 >/dev/null
[ "$(readlink "$dest")" = "$src" ] || fail "FORCE did not replace the symlink"
pass "FORCE replaces a foreign symlink"

# 7. a directory is always refused
rm -f "$dest"; mkdir "$dest"
if sh "$root/tools/install_plugin.sh" "$src" "$dest" 1 >/dev/null 2>&1; then
    fail "install accepted a directory"
fi
[ -d "$dest" ] || fail "directory was removed"
pass "directory protected"

echo "install guard: all checks passed"
