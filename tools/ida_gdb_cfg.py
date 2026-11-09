#!/usr/bin/env python3
"""Add (or remove) the Rosetta GDB register map in IDA's cfg/dbg_gdb.cfg.

IDA's Remote GDB backend needs to know the register feature the Rosetta stub
advertises (`com.apple.debugserver.x86_64`), otherwise it logs
"could not detect architecture from target info" and shows unknown registers.

Usage:
    ida_gdb_cfg.py --file <path/to/dbg_gdb.cfg> --check
    ida_gdb_cfg.py --file <path/to/dbg_gdb.cfg> --apply
    ida_gdb_cfg.py --file <path/to/dbg_gdb.cfg> --revert

`--apply` is idempotent, makes a timestamped backup before the first change and
never touches anything else in the file. Re-run it after every IDA upgrade if
you patch the installation copy directly (IDA replaces that file on update).

Exit codes: 0 ok / 1 not patched (for --check) / 2 error.
"""

import argparse
import datetime
import glob
import os
import sys

MARKER = "com.apple.debugserver.x86_64"

FEATURE_BLOCK = '''    "com.apple.debugserver.x86_64":
    {
      "title": "General registers",
      "rename": { "rflags": "EFL" },
      "code_ptr": "rip",
      "stack_ptr": "rsp",
      "frame_ptr": "rbp",
      "data_ptr":
      [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
      ]
    },
'''


def has_map(path):
    with open(path, "r", errors="ignore") as f:
        return MARKER in f.read()


def insert_map(text):
    lines = text.splitlines(True)
    for i, line in enumerate(lines):
        if line.strip().rstrip(":").strip() == '"i386:x86-64"':
            for j in range(i + 1, min(i + 4, len(lines))):
                if lines[j].strip().startswith("{"):
                    return "".join(lines[:j + 1] + [FEATURE_BLOCK] + lines[j + 1:])
    return None


def backup(path):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = "%s.bak-%s" % (path, stamp)
    with open(path, "rb") as src, open(dst, "wb") as out:
        out.write(src.read())
    return dst


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", required=True, help="path to dbg_gdb.cfg")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="exit 0 if patched")
    g.add_argument("--apply", action="store_true", help="add the register map")
    g.add_argument("--revert", action="store_true", help="restore newest backup")
    a = ap.parse_args()

    path = os.path.abspath(os.path.expanduser(a.file))
    if not os.path.isfile(path):
        print("error: no such file: %s" % path, file=sys.stderr)
        return 2

    if a.check:
        ok = has_map(path)
        print("%s: %s" % ("patched" if ok else "NOT patched", path))
        return 0 if ok else 1

    if a.apply:
        if has_map(path):
            print("already patched: %s" % path)
            return 0
        with open(path, "r", errors="ignore") as f:
            text = f.read()
        patched = insert_map(text)
        if patched is None:
            print('error: no "i386:x86-64" section found in %s' % path,
                  file=sys.stderr)
            return 2
        bak = backup(path)
        with open(path, "w") as f:
            f.write(patched)
        print("patched %s\nbackup  %s" % (path, bak))
        return 0

    baks = sorted(glob.glob(path + ".bak-*"))
    if not baks:
        print("error: no backup found for %s" % path, file=sys.stderr)
        return 2
    with open(baks[-1], "r", errors="ignore") as f:
        text = f.read()
    with open(path, "w") as f:
        f.write(text)
    os.unlink(baks[-1])
    print("reverted %s from %s" % (path, baks[-1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
