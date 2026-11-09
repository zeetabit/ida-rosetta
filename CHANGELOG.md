# Changelog

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
