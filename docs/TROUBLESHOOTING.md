# Troubleshooting

Start with `ida_kernwin.rosetta_doctor()` in the IDA console; it prints the
plugin version, launcher build state, stub path, config-patch state and the
target's runtime base.

## Symptoms

| symptom | cause | fix |
|---|---|---|
| F9 does nothing | target not selected, or not an x86_64 binary, or a debugger is already active | `ida_kernwin.rosetta_pick()`; check `target x86_64` in the doctor output |
| F9 returns instantly with no attach | `ProcessStart` action not intercepted (name changed / plugin not installed) | check the Output for `[rosetta] vX installed`; see COMPATIBILITY.md |
| `attach failed (-1)` | stub busy (`--attach`), process gone, or security software blocking | kill stale `rosetta/debugserver`, retry; add an exclusion |
| attach works but no breakpoint hits | target started with ASLR (addresses don't match); or plugin < 0.6.1, which passed `BPT_BRK` (1 = `BPT_WRITE`) as the breakpoint type and made IDA send `Z2` (rejected with `E09`) | restart with the launcher; upgrade to 0.6.1+; `rosetta_doctor()` shows both bases. A raw `Z0` at the address should produce `T05` |
| `could not detect architecture from target info` | `dbg_gdb.cfg` has no `com.apple.debugserver.x86_64` map | `ida_kernwin.rosetta_install_cfg()` + restart IDA |
| registers show as `?`, memory reads fail | same missing register map, or manual memory regions not configured | apply the config override; optionally set `Debugger → Manual memory regions` |
| `dbg_gdb.cfg` check fails after an IDA update | IDA replaced `cfg/dbg_gdb.cfg` and the old override became stale | re-run `rosetta_install_cfg()` (it refreshes from the new file) |
| launcher build fails | no clang, or the SDK cannot build arm64+x86_64 | `xcode-select --install`; rebuild via `rosetta_rebuild()`; error is in the Output |
| old launcher still used after an upgrade | build failed and the plugin fell back | Output says "rebuild failed; falling back"; fix the compiler and call `rosetta_rebuild()` |
| `task_info(TASK_BASIC_INFO) ... invalid destination port` (stub exits, code 3) | a previous client left the stub in a broken session | remove the stale stub; the plugin starts a fresh idle one |
| stub not listening | port taken / security software | `lsof -nP -iTCP:1239`; change `PORT` in the plugin |
| debugger UI freezes for minutes | *not* this plugin (it never calls `wait_for_next_event`) — check for other debugger scripts | see DESIGN.md "failure modes" |

## Diagnostics

```bash
# is the target traced?  'X' in STAT means yes
ps -o pid,stat,command -p "$(pgrep -x <program> | head -1)"

# is the stub up, and does it own a connection?
lsof -nP -iTCP:1239

# where did the target really load?
vmmap <pid> | grep __TEXT | grep <program>

# is the stub fast? (should be ~0.3 s for vAttach, ~0.3 s for 64 KB)
tests/rsp_probe.py --port 1239 --pid <pid>
```

`~/.idapro/plugins/ida-rosetta/stub.log` holds the stub's stderr.

## Known non-bugs

* `Debugger backend does not provide memory information` — the Rosetta stub has
  no memory map; IDA falls back. Harmless.
* The program printing a failure message after a success marker — that is
  application-specific (see `examples/fallingwhale_helper.py`).
