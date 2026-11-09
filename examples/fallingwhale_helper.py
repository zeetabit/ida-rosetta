# Example: app-specific helper for the FallingWhale crackme (crackmes.one).
#
# Load this with File > Script file... *after* the Rosetta debug plugin is
# installed. At the breakpoint on the MD5 comparison it writes the expected
# register code into the input buffer.
#
#     ida_kernwin.fw_solve()     # write the expected code
#     ida_kernwin.fw_go()        # continue
#
# Breakpoint: the call to the comparison helper (0x100003C78 in the shipped
# binary). At that point rdi points to the MD5 hex string, rsi is the number of
# characters compared, and rdx is the buffer holding the typed code.

import ida_kernwin
import ida_dbg
import idc


def fw_solve(cont=False):
    if not ida_dbg.is_debugger_on():
        ida_kernwin.msg("[fw] no debugger session\n")
        return None
    rdi = ida_dbg.get_reg_val("rdi")
    rsi = ida_dbg.get_reg_val("rsi")
    rdx = ida_dbg.get_reg_val("rdx")
    # IDA 9.x: idc.read_dbg_memory(ea, size) returns bytes;
    # ida_dbg.read_dbg_memory(ea, buffer, size) needs an out-buffer.
    raw = idc.read_dbg_memory(rdi, 64) or b""
    md5 = raw.split(b"\0")[0].decode("latin1")
    code = md5[:rsi]
    idc.write_dbg_memory(rdx, code.encode() + b"\0")
    ida_kernwin.msg("[fw] MD5=%s len=%d -> wrote %r to 0x%x\n"
                    % (md5, rsi, code, rdx))
    if cont:
        fw_go()
    return code


def fw_go():
    if ida_dbg.is_debugger_on():
        ida_dbg.continue_process()


ida_kernwin.fw_solve = fw_solve
ida_kernwin.fw_go = fw_go
ida_kernwin.msg("[fw] helper loaded: ida_kernwin.fw_solve() / fw_go()\n")
