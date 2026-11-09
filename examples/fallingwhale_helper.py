# FallingWhale (crackmes.one) as a *policy* on top of the generic ida-rosetta
# API. This is intentionally app-specific: it encodes what the reverse
# engineering found. The plugin itself knows nothing about FallingWhale.
#
# The policy has two stages, which is the useful pattern for input-driven
# targets whose scanf() gets disturbed by attach:
#
#   1. at make_and_check() entry: overwrite the two input buffers with known
#      values, so the hash is computed from data we control;
#   2. at compare_code() entry: read the expected MD5 and write the compared
#      prefix into the typed-code buffer, then resume.
#
# Load with File > Script file..., then call:
#
#     ida_kernwin.fw_attach()
#
# (The target must already be running under the noaslr launcher, or use
#  START=True below.)

import ida_kernwin
import idaapi

ENTRY = 0x100003B10        # make_and_check entry: inject inputs
COMPARE = 0x100003A40      # compare_code entry: expected/len/typed are live
START = False              # True = let the plugin launch the target

USERNAME = b"whale"
TYPED = b"AAAA"


def fw_solve(cont=False):
    """Manual helper: write expected[:len] into the typed buffer."""
    expected = ida_kernwin.rosetta_read_str(ida_kernwin.rosetta_reg("rdi"), 64)
    n = ida_kernwin.rosetta_reg("rsi")
    rdx = ida_kernwin.rosetta_reg("rdx")
    code = expected[:n]
    ok = ida_kernwin.rosetta_write(rdx, code.encode() + b"\0")
    ida_kernwin.msg("[fw] expected=%s len=%d wrote %r (%s)\n"
                    % (expected, n, code, "ok" if ok else "failed"))
    if cont:
        fw_go()
    return code


def fw_on_bpt(ctx):
    """Two-stage policy: inject once, then solve once."""
    if ctx.ea == ENTRY:
        ok1 = ctx.write(ctx.reg("rdi"), USERNAME + b"\0")
        ok2 = ctx.write(ctx.reg("rdx"), TYPED + b"\0")
        ida_kernwin.msg("[fw] entry: injected user=%r code=%r (%s/%s)\n"
                        % (USERNAME, TYPED, ok1, ok2))
        return "continue"

    if ctx.ea == COMPARE:
        expected = ctx.read_str(ctx.reg("rdi"), 64)
        n = ctx.reg("rsi")
        code = expected[:n]
        ok = ctx.write(ctx.reg("rdx"), code.encode() + b"\0")
        ida_kernwin.msg("[fw] compare: expected=%s len=%d wrote %r (%s)\n"
                        % (expected, n, code, "ok" if ok else "failed"))
        return "continue"

    return "stop"


def fw_go():
    return ida_kernwin.rosetta_go()


def fw_attach(pid=None, base=None):
    """Attach and run the two-stage policy.

    pid/base are optional fast paths: base skips the vmmap query, which keeps
    the call under IDA Assist's short cooperative script budget.
    """
    return ida_kernwin.rosetta_headless(
        path=idaapi.get_input_file_path(),
        pid=pid,
        base=base,
        start=START,
        breakpoints=["+0x3b10", "+0x3a40"],
        on_bpt=fw_on_bpt,
        run=True,
        wait_timeout=0,
        registers=(),
    )


ida_kernwin.fw_solve = fw_solve
ida_kernwin.fw_go = fw_go
ida_kernwin.fw_on_bpt = fw_on_bpt
ida_kernwin.fw_attach = fw_attach
ida_kernwin.msg("[fw] policy loaded: fw_attach() / fw_solve() / fw_go()\n")
