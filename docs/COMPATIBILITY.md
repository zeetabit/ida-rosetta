# Compatibility and upgrades

## Matrix

| component | tested | notes |
|---|---|---|
| IDA Pro | 9.5.261026 (arm64) | needs `arm64` IDA; x86_64 builds cannot load the plugin's assumptions |
| macOS | 26.7.1 (25G241) | Rosetta stub present since 11.0 |
| Rosetta stub | `/usr/libexec/rosetta/debugserver` (arm64e) | `/Library/Apple/usr/libexec/oah/debugserver` is a symlink to it; both are probed |
| Python | IDA's bundled 3.13 | no third-party modules |

## What depends on the IDA version

1. **Action names** — the plugin hooks `ProcessStart` (F9) and `ProcessAttach`.
   If a future IDA renames them, interception silently stops. Verify with:
   ```python
   import ida_kernwin
   print([a for a in ida_kernwin.get_registered_actions()
          if a in ("ProcessStart", "ProcessAttach")])
   ```
2. **`ida_dbg` API** — `attach_process`, `load_debugger`, `set_remote_debugger`,
   `add_bpt`, `DBG_Hooks`. Stable since 7.x.
3. **`idd.hpp`/`dbg_gdb.cfg`** — the register feature map can be replaced by an
   update; re-apply the override.
4. **Plugin ABI** — this is a Python plugin, so no rebuild is needed for a new
   IDA; only the launcher (C) is rebuilt, and only when its source changes.

## Post-upgrade checklist

```python
import ida_kernwin
ida_kernwin.rosetta_doctor()      # 1. everything green?
ida_kernwin.rosetta_rebuild()     # 2. rebuild the launcher against current tools
```

* `rosetta map present: True` — otherwise `rosetta_install_cfg()` + restart.
* `launcher state: vX, src ...` must show the current plugin version.
* `stub: /usr/libexec/rosetta/debugserver` (or the `oah` symlink).
* `target image base == ida image base` — otherwise the target has ASLR.
* `ui.intercept_f9` matches what you expect (default `false`), and
  `ui.f9_action` is the behaviour you want F9 to replay (`start` / `attach`).

## If the Rosetta menu is missing

The menu is created with `create_menu("Rosetta", "Rosetta", "Debugger/Start process")`
(anchored before *Start process*, top-level fallback). If an IDA build refuses
the anchor, the menu may appear at the top level instead of under *Debugger*;
actions are still attached to `"Rosetta/"`. Creating the menu **before**
attaching actions is required — a nested path alone does not create it.

## If the hook stops firing

Temporarily bind the plugin to its own hotkey instead of F9:

```python
import ida_kernwin
ida_kernwin.rosetta_attach()
```

Then open an issue with the doctor output and the two action names above.

## Removing

1. Remove the plugin (`make uninstall` if this checkout installed it).
2. Delete the plugin state directory (`$IDAUSR/plugins/ida-rosetta`;
   `~/.idapro` by default).
3. Delete the config override `$IDAUSR/cfg/dbg_gdb.cfg` if you no longer need it
   (IDA falls back to the installation copy).
