# Changelog

## 0.6.1
- **Fix: breakpoints never fired.** `add_bpt(ea, 1, BPT_BRK)` passed the
  `BPT_BRK` *flag* bit (1) where `add_bpt` expects a `bpttype_t`; the value 1
  means `BPT_WRITE`, so IDA sent `Z2,addr,1` (a one-byte write watchpoint) and
  the Rosetta stub rejected it with `E09`. Software execution breakpoints need
  `add_bpt(ea, 0, BPT_SOFT)`, which IDA sends as `Z0` and the stub accepts.
  Reported by a live `Z0 -> T05` test at `0x100003c78`.
- Both call sites (`rosetta_headless(breakpoints=...)` and the stored
  `break_off` used by `rosetta_attach()`) now go through `_add_code_bpt()`.
- `BPT_SOFT` is not exported by `ida_dbg`, so it is derived at runtime from
  `ida_dbg.bpt_t().type` (the constructor initializes it to `BPT_SOFT`) with
  `4` only as a last-resort fallback.
- CI/Makefile guard against reintroducing `add_bpt(..., BPT_BRK)`.

## 0.6.0

- **Headless support**: `rosetta_headless()` (UI-free) plus
  `tools/rosetta_headless.py`, usable from `idat -A -S"..."`. The GUI parts
  (menus, actions, dialogs, F9 hook) are skipped when `is_idaq()` is false.
- Debugger events are pumped explicitly (`wait_for_next_event`) because there is
  no GUI event loop; verified `attach_process -> 1` and register reads in
  text mode.
- `rosetta_detach()` helper.

## 0.5.0
- **F9 replays the last explicit action**: `Pick and start…` makes F9
  start+attach; `Attach to running target` / `Attach by process…` make F9
  attach. Stored as `ui.f9_action` (`LAUNCH_MODE` removed).
- `ida_kernwin.rosetta_set_f9_mode("start"|"attach")` helper.

## 0.4.0
- **F9 interception is opt-in and off by default**: checkable
  `Use for F9 / Attach to process` in both Rosetta submenus, persisted as
  `ui.intercept_f9`. When off, IDA handles `ProcessStart`/`ProcessAttach`
  natively and a one-time hint is logged.

## 0.3.1
- Start dialog now has **OK / Cancel** buttons (the previous template used
  `BUTTON … NONE`, which hides them in IDA).
- Second `Rosetta` submenu next to the plugin entry (`Edit → Plugins`);
  the command-chooser window was removed and the plugin entry runs
  *Pick and start…* again.
- `uninstall()` detaches from both menus and deletes them.

## 0.3.0
- `Debugger → Rosetta` submenu. Root cause of the missing menu:
  `attach_action_to_menu("Debugger/", …)` returns `False` — nested paths only
  resolve for menus that already exist, so the menu is created first
  (`create_menu`) and actions are attached to `"Rosetta/"`.

## 0.2.0
- Start dialog: program path, arguments, working directory, environment
  (`KEY=VALUE`), launched through the bundled `noaslr`.
- Attach by process: modal chooser (PID/name/command, executables first) with
  the chooser's search filter.
- Explicit menu actions attached to `Debugger/`; launcher rebuilds are keyed on
  the embedded C source hash only (UI-only releases no longer recompile).

## 0.1.0
- Initial release: `ProcessStart`/`ProcessAttach` interception, generic target
  selection (per-idb setting → input file → picker), universal `noaslr`
  launcher embedded as **source** and built on first use with version/source-hash
  stamping and atomic replacement, `dbg_gdb.cfg` override installer,
  `rosetta_doctor()`, RSP probe, CI.
