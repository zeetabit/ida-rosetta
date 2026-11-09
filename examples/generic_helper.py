"""Generic ida-rosetta target script (template for any x86_64 Mach-O).

The plugin already handles the Rosetta-specific mechanics: finding the process,
starting the arm64 debugserver, matching the image base, attaching, and adding
software breakpoints. This file is the *policy* layer: which address is
interesting and what to do when it is hit.

Usage
-----
1. Build a database for the binary and open it in IDA (arm64 build).
2. Start the app so its addresses match the database::

       ~/.idapro/plugins/ida-rosetta/noaslr /path/to/app

   (or set START = True below and let the plugin launch it)
3. Edit TARGET, BREAKPOINTS and on_bpt().
4. Load this file with File > Script file..., then::

       ida_kernwin.rosetta_example_attach()

Breakpoint specifications
-------------------------
    0x100003c78 / 4294982776    absolute address
    "+0x3c78" / "rva:0x3c78"    offset from the image base
    "main" / "my_symbol"        IDA name
    "AppName+0x3c78"            executable basename/stem + offset

Everything in on_bpt() is ordinary IDAPython; the ctx object is just a
convenience wrapper around ida_dbg / idc:

    ctx.ea                  address that was hit
    ctx.tid                 thread id
    ctx.reg("rdi")          register value
    ctx.regs()              common x86_64 registers as a dict
    ctx.read(ea, size)      bytes
    ctx.read_str(ea, n)     NUL-terminated string
    ctx.write(ea, data)     write bytes (or str)
    ctx.continue_now()      resume immediately
    ctx.stop()              leave the process suspended

Return "continue" (or True) from on_bpt() to resume automatically; any other
return value leaves the process stopped for inspection.
"""

import ida_kernwin

# ---------------------------------------------------------------- policy
TARGET = "/path/to/x86_64/app"
START = False                      # True = let the plugin launch it
BREAKPOINTS = ["main"]             # absolute, +offset, name, or App+offset


def on_bpt(ctx):
    """Called on every breakpoint in BREAKPOINTS. Edit this."""
    rdi = ctx.reg("rdi")
    print("[generic] hit 0x%x  rdi=0x%x rsi=0x%x rdx=0x%x"
          % (ctx.ea, rdi, ctx.reg("rsi"), ctx.reg("rdx")))
    text = ctx.read_str(rdi, 128)
    if text:
        print("[generic] string@rdi = %r" % text)
    return "stop"                  # or "continue"
# -----------------------------------------------------------------------


def attach():
    result = ida_kernwin.rosetta_headless(
        path=TARGET,
        start=START,
        breakpoints=BREAKPOINTS,
        on_bpt=on_bpt,
        run=True,
        wait_timeout=60,
        registers=("rip", "rdi", "rsi", "rdx"),
    )
    print("[generic] %r" % (result,))
    return result


ida_kernwin.rosetta_example_attach = attach
print("[generic] loaded: edit TARGET/BREAKPOINTS, then "
      "ida_kernwin.rosetta_example_attach()")
