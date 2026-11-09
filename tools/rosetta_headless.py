#!/usr/bin/env python3
"""Headless driver for the Rosetta debug plugin.

Run inside IDA's text-mode binary:

    idat -A -S"tools/rosetta_headless.py --pid 1234 --bp 0x100003c78 \
          --run --wait 10 --regs rdi,rsi,rdx --json /tmp/run.json" db.i64

or let it start the program itself (needs the bundled launcher):

    idat -A -S"tools/rosetta_headless.py --target /path/to/prog --start \
          --stdin /tmp/prog.stdin --json /tmp/run.json" db.i64

Results are written to --json (default /tmp/rosetta_headless.json) because
IDAPython output is not reliably captured in text mode. Exit status: 0 if the
plugin reported ok, 1 otherwise.
"""

import argparse
import json
import os
import sys

import idc


def load_plugin():
    mod = sys.modules.get("__plugins__rosetta")
    if mod is not None:
        return mod
    import importlib.util
    path = os.path.expanduser("~/.idapro/plugins/rosetta.py")
    spec = importlib.util.spec_from_file_location("rosetta_headless_plugin", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="rosetta_headless")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--target", default=None)
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--args", default=None)
    ap.add_argument("--cwd", default=None)
    ap.add_argument("--env", default=None)
    ap.add_argument("--stdin", dest="stdin_path", default=None)
    ap.add_argument("--bp", action="append", default=[],
                    help="breakpoint spec: 0x..., +0x..., rva:0x..., NAME, "
                         "App+0x... (repeatable)")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--wait", type=float, default=0.0)
    ap.add_argument("--regs", default="")
    ap.add_argument("--detach", action="store_true")
    ap.add_argument("--json", default="/tmp/rosetta_headless.json")
    return ap.parse_args(argv)


def main():
    argv = list(getattr(idc, "ARGV", []))
    script = argv[0] if argv else ""
    args = parse_args(argv[1:] if len(argv) > 1 else [])

    out = {"argv": argv}
    try:
        mod = load_plugin()
        out["plugin_version"] = getattr(mod, "__version__", "?")
        res = mod.rosetta_headless(
            path=args.target,
            pid=args.pid,
            args=args.args,
            env=args.env,
            cwd=args.cwd,
            start=args.start,
            stdin_path=args.stdin_path,
            breakpoints=args.bp,
            run=args.run,
            wait_timeout=args.wait,
            registers=[r for r in args.regs.split(",") if r],
        )
        out["result"] = res
        if args.detach and res.get("ok"):
            out["detached"] = mod.rosetta_detach()
    except Exception:
        import traceback
        out["exception"] = traceback.format_exc()

    with open(args.json, "w") as f:
        json.dump(out, f, indent=2)

    rc = 0 if out.get("result", {}).get("ok") else 1
    idc.qexit(rc)


main()
