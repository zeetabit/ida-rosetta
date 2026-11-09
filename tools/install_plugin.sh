#!/bin/sh
# Install (or verify) the plugin symlink without clobbering user files.
#
# Usage: install_plugin.sh SRC DEST [FORCE]
#   SRC    absolute path to plugin/rosetta.py
#   DEST   target path, e.g. ~/.idapro/plugins/rosetta.py
#   FORCE  1 = replace an existing non-matching file/symlink (file is backed up)
set -eu

src=$1
dest=$2
force=${3:-0}

[ -f "$src" ] || { echo "error: source not found: $src" >&2; exit 1; }
mkdir -p "$(dirname "$dest")"

if [ -L "$dest" ]; then
    cur=$(readlink "$dest" 2>/dev/null || true)
    if [ "$cur" = "$src" ]; then
        echo "already installed: $dest -> $src"
        exit 0
    fi
    if [ "$force" != "1" ]; then
        echo "refusing: $dest is a symlink to ${cur:-<broken>}" >&2
        echo "  remove it manually, or run 'make install FORCE=1' to replace it" >&2
        exit 1
    fi
    echo "replacing symlink: $dest -> ${cur:-<broken>}"
    rm -f "$dest"
elif [ -e "$dest" ]; then
    if [ -d "$dest" ]; then
        echo "refusing: $dest is a directory" >&2
        exit 1
    fi
    if [ "$force" != "1" ]; then
        echo "refusing: $dest exists and is not a symlink" >&2
        echo "  move it away, or run 'make install FORCE=1' to back it up and link" >&2
        exit 1
    fi
    backup="$dest.bak.$(date +%Y%m%d-%H%M%S)"
    mv "$dest" "$backup"
    echo "backed up existing file: $backup"
fi

ln -s "$src" "$dest"
echo "installed: $dest -> $src"
