# Example: FallingWhale (crackmes.one) as a *policy* on top of the generic
# ida-rosetta API. This is intentionally app-specific: it encodes the result of
# the reverse engineering (rdi = expected MD5 hex, rsi = compared length,
# rdx = typed-code buffer). The plugin knows nothing about FallingWhale.
#
# Load with File > Script file... after the plugin is installed. Then either
# press F9 / attach normally, or let this file do it:
#
#     ida_kernwin.fw_attach()    # attach and auto-solve on the breakpoint
#
# Manual use at the breakpoint:
#
#     ida_kernwin.fw_solve()     # write the expected code
#     ida_kernwin.fw_go()        # continue
#
# Breakpoint: the call to the comparison helper (0x100003C78, or the IDA name
# "compare_code" / image offset "+0x3c78" in the shipped binary).

import ida_dbg
import ida_kernwin


def fw_solve(cont=False):
    if not ida_dbg.is_debugger_on():
        ida_kernwin.msg("[fw] no debugger session\n")
        return None
    rdi = ida_kernwin.rosetta_reg("rdi")
    rsi = ida_kernwin.rosetta_reg("rsi")
    rdx = ida_kernwin.rosetta_reg("rdx")
    md5 = ida_kernwin.rosetta_read_str(rdi, 64)
    code = md5[:rsi]
    ok = ida_kernwin.rosetta_write(rdx, code.encode() + b"\0")
    ida_kernwin.msg("[fw] MD5=%s len=%d -> wrote %r to 0x%x (%s)\n"
                    % (md5, rsi, code, rdx, "ok" if ok else "failed"))
    if cont:
        fw_go()
    return code


def fw_on_bpt(ctx):
    """Generic on-hit callback: solve and resume."""
    md5 = ctx.read_str(ctx.reg("rdi"), 64)
    code = md5[:ctx.reg("rsi")]
    ctx.write(ctx.reg("rdx"), code.encode() + b"\0")
    return "continue"


def fw_go():
    return ida_kernwin.rosetta_go()


def fw_attach():
    """Attach to a running FallingWhale and auto-solve at the comparison."""
    return ida_kernwin.rosetta_headless(
        path=ida_kernwin.get_input_file_path(),
        breakpoints=["+0x3c78"],
        on_bpt=fw_on_bpt,
        run=True,
        wait_timeout=30,
        registers=("rdi", "rsi", "rdx"),
    )


ida_kernwin.fw_solve = fw_solve
ida_kernwin.fw_go = fw_go
ida_kernwin.fw_on_bpt = fw_on_bpt
ida_kernwin.fw_attach = fw_attach
ida_kernwin.msg("[fw] helper loaded: fw_attach() / fw_solve() / fw_go()\n")
