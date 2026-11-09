# Design notes

## Objective

Make IDA's normal debugger usable on an x86_64 process running under Rosetta on
Apple Silicon, without reimplementing a debugger backend.

## Mechanism

IDA's **Remote GDB** backend and Apple's **Rosetta GDB stub** speak the same
protocol. Everything the user sees after the attach is IDA's own engine. The
only non-standard step is the entry point: the stub implements no `vFile`, so
IDA cannot launch through it — a process must already exist, and IDA must
*attach*.

```
F9 / Attach to process
        │
        ├─ resolve target (per-idb setting → idb input file)
        ├─ verify x86_64 slice (lipo -archs)
        ├─ find process (pgrep -x <name[:16]>, pgrep -f <name>), verify via vmmap
        ├─ require runtime __TEXT base == idaapi.get_imagebase()
        ├─ ensure an *idle* /usr/libexec/rosetta/debugserver on 127.0.0.1:1239
        ├─ ida_dbg.set_remote_debugger(); ida_dbg.load_debugger("gdb", True)
        ├─ optional breakpoint at base + settings["break_off"]
        ├─ ida_dbg.attach_process(pid, -1)
        └─ ida_dbg.continue_process()
```

The target must load at the database's base, hence the bundled `noaslr`
launcher (`posix_spawn` with `POSIX_SPAWN_DISABLE_ASLR = 0x0100`).

### F9 semantics

Taking over IDA's own actions is opt-in (`ui.intercept_f9`, default off) and,
when enabled, F9 *replays the last explicit action* rather than always doing the
same thing:

| last menu action | F9 behaviour |
|---|---|
| `Pick and start…` | if not running: launch with the stored args/cwd/env, then attach; if running: just attach |
| `Attach to running target`, `Attach by process…` | attach; if not running, print the launcher command |

The choice lives in `ui.f9_action` (`start` / `attach`), so the plugin never
surprises you by spawning a second copy of the target.

## Evidence

### IDA 9.5 arm64 ships no Rosetta support

| file | arch | comment |
|---|---|---|
| `plugins/arm_mac_user.dylib` | arm64 | "Local ARM Mac OS debugger" |
| `plugins/mac_user.dylib` | x86_64 | cannot be loaded by arm64 IDA |
| `plugins/pin_user.dylib` | x86_64 | "PIN cannot be run on Mac (yet)" |
| `plugins/gdb_user.dylib` | arm64 | the backend used here |
| `dbgsrv/mac_server*` | x86_64 / arm64 | signed `com.apple.security.cs.debugger`, use `task_for_pid` |

`grep -a -r -i rosetta` over the whole bundle: **0 hits** in `ida`,
`libida.dylib`, `arm_mac_user`, `mac_user`, `mac_server`, `mac_server_arm`,
`gdb_user`. Only the dyld-shared-cache loader mentions Rosetta (static
analysis).

### The stub is fast (measured)

`qSupported` advertises `qXfer:features:read+;PacketSize=20000;qEcho+;native-signals+`.

| packet | result | time |
|---|---|---|
| `vAttach;<pid>` | `T11thread:…` | **0.276 s** |
| `g` (registers) | 1160 B | 0.001 s |
| `m addr,0x1000` | 4 KB | 0.007 s |
| `m addr,0x10000` | 64 KB | 0.328 s |
| `qXfer:features` | target.xml, 1025 B | 0.001 s |
| `qMemoryRegionInfo` | `start:100000000;size:4000;permissions:rx` | 0.000 s |
| `vCont;c` | reply only on stop | — |

Sixteen additional packets (threads, libraries-svr4, `qProcessInfo`,
`jThreadsInfo`, `vFile:open`, …) were probed: all answered, none silently
dropped. Slow behaviour in IDA is therefore never the stub.

### Failure modes and their real causes

| symptom | cause |
|---|---|
| `request_attach_process()` returns 1, nothing happens | it only queues a request; IDA services that queue only while a session already exists |
| `wait_for_next_event(WFNE_SUSP, …)` hangs until a manual Suspend | attaching is not a suspend *transition*; the wait never completes |
| IDA deadlocks on `QBasicReadWriteLock::contendedTryLockForWrite` | UI/debugger calls made from an `ida_kernwin.register_timer` callback |
| `could not detect architecture from target info` | `dbg_gdb.cfg` lacks the stub's register feature `com.apple.debugserver.x86_64` |

## Implementation

### Files

```
plugin/rosetta.py        the whole plugin (also embeds the launcher C source)
launcher/noaslr.c        ASLR-disabling launcher, kept in sync with the copy
tools/ida_gdb_cfg.py     standalone patcher for cfg/dbg_gdb.cfg
tests/rsp_probe.py       RSP latency probe (bug reports)
examples/                app-specific helper example
```

### State (user dir)

```
$IDAUSR/plugins/ida-rosetta/noaslr         built launcher (universal)
$IDAUSR/plugins/ida-rosetta/noaslr.c       extracted source
$IDAUSR/plugins/ida-rosetta/launcher.json  {plugin_version, c_source_sha256, cc, arch_flags, built_at}
$IDAUSR/plugins/ida-rosetta/settings.json  {schema, targets: {<idb>: {path, args, break_off}}}
$IDAUSR/plugins/ida-rosetta/stub.log       stub stderr
$IDAUSR/cfg/dbg_gdb.cfg                    config override (register map)
```

### Versioning and rebuilds

The launcher is built from source, never shipped. Each build records the plugin
version and the SHA-256 of the embedded C source. `_launcher()` rebuilds when
either changes or when the binary is missing; the build goes to a temporary
file and is swapped in with `os.replace`, so a failed compile cannot destroy a
working install. If rebuilding fails, the plugin keeps the previous binary and
warns. `rosetta_rebuild()` forces it.

Build variants, in order: universal (`-arch arm64 -arch x86_64`), host arch
only, no arch flags. The `cc` used and the chosen flags are recorded in
`launcher.json` for diagnosis.

### Config override instead of patching the app bundle

IDA searches `$IDAUSR/cfg` before its installation `cfg`. The plugin therefore
writes a **user-level** `dbg_gdb.cfg` that adds the stub's register feature,
leaving `/Applications/IDA…` untouched and requiring no `sudo`.
`rosetta_install_cfg()` copies the installation file and inserts:

```json
"com.apple.debugserver.x86_64":
{
  "title": "General registers",
  "rename": { "rflags": "EFL" },
  "code_ptr": "rip",
  "stack_ptr": "rsp",
  "frame_ptr": "rbp",
  "data_ptr": [ "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" ]
},
```

`tools/ida_gdb_cfg.py --check|--apply|--revert` does the same to any single
file (used in CI and for scripted setups).

### Settings schema

`settings.json` is `{"schema": 1, "targets": {<idb path>: {...}}}`. Files from
the 0.x flat layout (`<idb path> -> {...}`) migrate on read.

## Design rules (constraints discovered while building this)

1. Never call `wait_for_next_event(WFNE_SUSP, …)` after attaching.
2. Never call `request_attach_process()` from an action handler; use
   `attach_process()`.
3. Never do UI/debugger work from an `ida_kernwin.register_timer` callback.
4. No modal dialogs on the automatic F9 path; log to Output and beep.
5. Do not rebase the database per run; make the target load at the database's
   base instead.
6. The stub must be idle (no `--attach`); IDA sends `vAttach`.
7. Probe "is the stub listening?" with `lsof`, never with a TCP connect — the
   stub exits when its only client disconnects.
8. `attach_action_to_menu("Debugger/", …)` returns `False`: nested menu paths
   only resolve for menus that already exist. Create the menu first
   (`create_menu(name, label, anchor)`), then attach to `"<name>/"`.
9. In `ida_kernwin.Form`, `BUTTON YES/NO/CANCEL NONE` **hides** that button.
   A dialog with OK/Cancel is `BUTTON YES* OK`, `BUTTON NO NONE`,
   `BUTTON CANCEL Cancel`.

## Alternatives

| approach | verdict |
|---|---|
| **Python action hook (this)** | same engine, ~1 day; no debugger-selector entry |
| Native `debugger_t` module | the only way to get a real entry; self-contained but needs an RSP client (~1.5–2.5k LOC, 2–4 weeks). Delegating to `gdb_user` is impossible: no API exposes another backend's `debugger_t*` |
| Patch `arm_mac_user`/`mac_server_arm` | breaks signatures, per-version maintenance |
| Run the x86_64 IDA under Rosetta | still `task_for_pid`-based, not the Rosetta stub |
| LLDB/Ghidra for execution | works (LLDB spawns the Rosetta stub natively) but loses IDA's debugger |
| Upstream feature request | the correct long-term fix: IDA's macOS backend should spawn the Rosetta stub for translated processes — it already owns the GDB transport |

### Can IDA use LLDB?

No built-in LLDB backend ships with IDA 9.5: the debugger modules are
`arm_mac_user`, `gdb_user`, `ios_user`, `xnu_user`, `linux`, … (there is no
`lldb_user`). The `lldb` strings in `libida` are DWARF/compiler tuning flags
(`-debugger-tuning=lldb`), and the `dbg_ios.cfg`/`dbg_xnu.cfg` mentions are
background on Apple's RNBRemote.

IDA can connect to a **GDB RSP server** — which is exactly what this plugin
does with `/usr/libexec/rosetta/debugserver` — but it cannot drive LLDB as a
backend. A process has one debugger owner; LLDB and IDA cannot both own it.
Using LLDB means using LLDB's debugger UI, and losing IDA's database,
decompiler and scripting. An LLDB-backed IDA plugin would have to implement
`debugger_t` and delegate to LLDB's SB API; that is a much larger project than
the RSP bridge and has no Rosetta-specific advantage.

### What IDA's docs say about custom debuggers

`idd.hpp` is *"Debugger plugin API for debugger module writers"*; `dbg.hpp` is
the control API. A debugger entry **is** a native plugin: `plugin_t::init()`
returns a `debugger_t*`, and since IDA 7.1 the module implements a single
`notify(event_t, …)` dispatcher, with capabilities gated by `DBG_HAS_*` flags.
A module can declare `DBG_FLAG_DISABLE_ASLR`, which makes IDA show *Disable
ASLR* in its own debugger options. There is no config- or script-level way to
add an entry.

### Native `HT_IDD` listener spike (result)

A throwaway probe plugin (not shipped) hooked `HT_IDD` and logged every
notification while the built-in gdb backend was the active debugger:

* a plugin that is **not** the active debugger module receives the whole event
  stream: `ev_init_debugger`, `ev_start_process` (with path/args/dir/flags),
  `ev_attach_process` (with pid), `ev_get_debug_event`, `ev_resume`,
  `ev_exit_process`, `ev_term_debugger`, …;
* returning `1` for `ev_start_process`/`ev_attach_process` **suppresses** the
  gdb backend's own handling (verified: with a claim on `ev_attach_process`,
  gdb never saw it; with a claim on `ev_start_process`, the vFile prompt
  disappeared). Nothing else performs the operation, so IDA then spins on
  `ev_get_debug_event` — a takeover listener must implement the launch/attach
  itself.

Implication: the F9 override could be moved from
`ida_kernwin.UI_Hooks.preprocess_action` down to the debugger notification
layer. It is still **not** a debugger-list entry (that requires a full
`debugger_t` module, see §6), and it would be a C++ port of the existing glue
with a binary per IDA version. The Python plugin stays the cheaper option;
this note exists so a future native rewrite starts from facts.

## References

* Apple, *About the Rosetta translation environment* — `sysctl.proc_translated`.
* LLVM/LLDB, `lldb/source/Plugins/Process/gdb-remote/ProcessGDBRemote.cpp` —
  spawns `/Library/Apple/usr/libexec/oah/debugserver` when
  `Host::IsProcessTranslated()`; the same policy implemented here.
* IDA docs, *Debugging Mac OSX Applications with IDA Pro* — arm64 debugging
  since 7.6, nothing about translated processes.
* IDA SDK headers, `idd.hpp` (`debugger_t`, `DBG_FLAG_DISABLE_ASLR`,
  `DBG_HAS_*`).

## Case study

A public crackme is used as the end-to-end check: a `scanf`-driven program that
compares a prefix of `MD5(user-chosen slice)` with a typed code. With the
plugin attached, a breakpoint on the comparison shows `rdi` = MD5 hex,
`rsi` = number of characters compared, `rdx` = input buffer; writing
`md5[:rsi]` yields the program's success path. See
`examples/fallingwhale_helper.py`. The binary is not included.
