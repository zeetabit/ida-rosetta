# Usage

A practical walkthrough of every entry point, what it does internally, and how
the pieces fit together. For installation see [../README.md](../README.md); for
failures see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

The plugin never replaces IDA's debugger: it starts the Rosetta stub and
attaches IDA's **Remote GDB** backend to it. Registers, memory, breakpoints,
stepping and modules are then handled by IDA as usual.

---

## 1. Before the first run

One-time: make IDA's GDB backend aware of the stub's register feature.

```python
ida_kernwin.rosetta_install_cfg()   # writes $IDAUSR/cfg/dbg_gdb.cfg
```

Restart IDA afterwards. This is a *user-level override*; the application bundle
is not modified and `sudo` is not needed.

Then check the environment:

```python
ida_kernwin.rosetta_doctor()
```

A healthy report looks like this (values vary):

```
plugin version          : 0.5.0
IDA version             : 9.5 (arm64)
launcher                : ~/.idapro/plugins/ida-rosetta/noaslr [ok]
launcher state          : v0.5.0, src 04e2c8bad95a
stub                    : /usr/libexec/rosetta/debugserver
stub listening          : False
dbg_gdb.cfg (install)   : /Applications/IDA…/cfg/dbg_gdb.cfg
dbg_gdb.cfg (effective) : /Applications/IDA…/cfg/dbg_gdb.cfg
rosetta map present     : True
target                  : /path/to/program
target x86_64           : True
target pid              : -
target image base       : -
ida image base          : 0x100000000
```

`rosetta map present: False` means step 1 is still needed. `target image base`
and `ida image base` must be equal once a program is running — otherwise it has
ASLR (see §4).

---

## 2. The menu

The same actions live in two places:

* **`Debugger → Rosetta`** — the primary submenu.
* **`Edit → Plugins → Rosetta`** — a second submenu next to the plugin entry.

The plugin entry itself (`Edit → Plugins → "Rosetta debug"`) runs **Pick and
start…**.

| entry | what it does |
|---|---|
| **Pick and start…** | Opens a dialog (§7). Stores the choice for this database, starts the program through the bundled launcher in a Terminal window, waits for its PID and attaches. |
| **Pick program…** | File picker only. Stores the program for this database; starts nothing. Useful when you want to launch it yourself. |
| **Attach by process…** | Modal process list (§5). Selecting a row resolves the executable, stores it as the target and attaches. |
| **Attach to running target** | Attaches to the program stored for this database. Prints the launcher command if it is not running. |
| **Doctor / prerequisites** | Prints the report from §1 to the Output window. |
| **Rebuild launcher** | Forces a rebuild of `noaslr` from the embedded C source (normally automatic). |
| **Use for F9 / Attach to process** | Checkable toggle. Off by default; controls whether the plugin intercepts IDA's own actions (§6). |

Everything the plugin does is written to the Output window, prefixed with
`[rosetta]`.

---

## 3. Workflow: start a program and debug it

1. `Debugger → Rosetta → Pick and start…`
2. Fill in at least **Program path**; optionally arguments, working directory
   and environment.
3. **OK**.

The plugin builds

```
cd <working dir> && env KEY=VALUE … <launcher> <program> <arguments>
```

and runs it in a new Terminal window (Apple Events). The program keeps that
window's stdin/stdout, so interactive programs behave normally: type into it.

Then it waits (up to 8 s) for a process whose executable matches the path,
checks that it loaded at the database's image base, starts an idle Rosetta stub
on `127.0.0.1:1239` if needed, attaches IDA's Remote GDB backend, applies the
database's breakpoints and continues.

If the program is **already running**, it is not started a second time — the
plugin just attaches to it.

---

## 4. Workflow: attach to an already running program

The program must already be running, and it must have loaded at the database's
image base (`0x100000000` for a default PIE). Start it with the bundled
launcher:

```bash
~/.idapro/plugins/ida-rosetta/noaslr /path/to/program [args…]
```

The launcher prints the child PID, keeps stdin/stdout attached to the terminal,
forwards `SIGINT`/`SIGTERM`/`SIGHUP`, and exits with the program's status. It is
universal (`arm64` + `x86_64`), so it runs natively on both Apple Silicon and
Intel Macs.

Then:

* `Debugger → Rosetta → Attach to running target`, or
* `F9` if the plugin's interception is enabled and the last action was an
  attach (§6).

Checks performed before attaching:

1. The process is found by executable name (`pgrep -x`, then `pgrep -f`) and
   confirmed through `vmmap` (the full path must appear).
2. Its `__TEXT` base equals `idaapi.get_imagebase()`. If not, the plugin prints
   the launcher command and stops — the addresses would not match the database.
3. The Rosetta stub is listening (started if absent, always *idle*, no
   `--attach`).
4. `attach_process(pid, -1)` succeeds; the plugin then continues execution.

The result is a completely ordinary IDA debug session: set breakpoints (F2),
step, inspect registers and memory.

---

## 5. Workflow: attach by process

`Debugger → Rosetta → Attach by process…` opens a modal list with three
columns: **PID**, **Name**, **Command**. Rows are sorted so processes with a
real executable path come first; the list's search field filters as you type
(name substring).

On **OK**, the plugin:

1. resolves the selected PID's executable through `vmmap`;
2. refuses it if it has no `x86_64` slice;
3. stores it as this database's target;
4. attaches (same checks as §4).

This is the quickest way to pick up a program that is already running, without
knowing its PID.

---

## 6. F9 behaviour

The plugin can take over IDA's `ProcessStart` (F9) and `ProcessAttach`
(`Debugger → Attach to process…`). That is **opt-in**, because replacing IDA's
own actions should be a decision:

* **`Use for F9 / Attach to process`** — unchecked by default.
* While unchecked, the plugin does not touch those actions; IDA handles them
  natively (and fails for a translated x86_64 target). Menu actions still work.
* While checked, F9 **replays the last explicit action** you used:

| last menu action | F9 |
|---|---|
| Pick and start… | if the program runs: attach; if not: start it (same args/cwd/env) and attach |
| Attach to running target / Attach by process… | attach; if it does not run, print the launcher command |

Both settings are global (all databases), stored under `ui` in
`settings.json` (§8), and survive restarts. Change the behaviour any time by
using a menu action, or from the console:

```python
ida_kernwin.rosetta_toggle_intercept()      # on/off
ida_kernwin.rosetta_set_f9_mode("start")    # or "attach"
```

---

## 7. The start dialog

| field | meaning |
|---|---|
| **Program path** | Executable to launch. `…` opens a file picker; must have an `x86_64` slice. |
| **Arguments** | Appended verbatim to the command line (shell syntax; quote spaces yourself). |
| **Working directory** | Used for `cd` before launching. Defaults to the program's directory. |
| **Environment** | `KEY=VALUE`, separated by spaces or newlines. Parsed with shell rules; values with spaces need quotes. Malformed input is rejected before anything starts. |

All four are stored per database, so the next *Pick and start…* is pre-filled.

If the form API is unavailable, the plugin falls back to a plain file picker.

---

## 8. Settings

`~/.idapro/plugins/ida-rosetta/settings.json` (or under `$IDAUSR` when set):

```json
{
  "schema": 1,
  "ui": {
    "intercept_f9": false,
    "f9_action": "attach"
  },
  "targets": {
    "/path/to/database.i64": {
      "path": "/path/to/program",
      "args": "-v",
      "cwd": "/path/to",
      "env": "LANG=C",
      "break_off": "3C78"
    }
  }
}
```

| key | scope | meaning |
|---|---|---|
| `ui.intercept_f9` | global | take over F9 / Attach to process |
| `ui.f9_action` | global | `start` or `attach` — what F9 replays |
| `targets.<idb>.path` | per database | program to debug |
| `targets.<idb>.args` / `.cwd` / `.env` | per database | used by *Pick and start…* and by F9 in `start` mode |
| `targets.<idb>.break_off` | per database | optional hex offset from the image base for an automatic breakpoint; without it only the database's own breakpoints are used |

Old (0.x) flat settings files are migrated automatically. Editing the file by
hand is fine; the plugin reads it on demand.

---

## 9. Console helpers

```python
ida_kernwin.rosetta_start()             # Pick and start dialog
ida_kernwin.rosetta_pick()              # file picker only
ida_kernwin.rosetta_attach()            # attach to the stored target
ida_kernwin.rosetta_attach_pid()        # process chooser
ida_kernwin.rosetta_go()                # continue
ida_kernwin.rosetta_goto()              # jump to the current IP
ida_kernwin.rosetta_doctor()            # environment report
ida_kernwin.rosetta_rebuild()           # force launcher rebuild
ida_kernwin.rosetta_install_cfg()       # write the dbg_gdb.cfg override
ida_kernwin.rosetta_toggle_intercept()  # F9 interception on/off
ida_kernwin.rosetta_set_f9_mode(mode)   # "start" or "attach"
```

---

## 10. A typical session

1. Open the database; confirm `rosetta_doctor()` is green (§1).
2. `Debugger → Rosetta → Pick and start…`; fill the path; **OK**.
3. A Terminal window opens and the program prompts. Leave it there.
4. IDA attaches in about a second; the Output shows
   `attach_process(pid=…) -> 1 after 0.3s` and `running (total 0.4s)…`.
5. Set breakpoints with F2 where you need them, then interact with the program
   in its Terminal window. IDA stops at the breakpoints.
6. Inspect/modify registers and memory as usual; continue with F9 (IDA's own
   continue, since a session is active).
7. Finish with `Debugger → Terminate process` (Ctrl-F2) or *Detach from
   process*.

---

## 11. Several programs and databases

* The target is stored **per database** (keyed by the `.i64` path). Reopen a
  database and its target is still there.
* To switch targets: *Pick program…*, *Pick and start…* or *Attach by process…*
  — each overwrites the stored target for the current database.
* One stub port (`1239`) is used per IDA instance. Running two IDA instances
  that both want to attach at the same moment is not supported; change `PORT`
  in the plugin for the second instance if you need it.

---

## 12. Cleanup

* Terminating or detaching the debuggee leaves the plugin idle; the stub exits
  when IDA disconnects.
* `~/.idapro/plugins/ida-rosetta/` holds the built launcher, the extracted
  source, `launcher.json`, `settings.json` and `stub.log`. Deleting it is safe:
  the launcher is rebuilt on demand.
* `make uninstall` only removes the plugin symlink; state is left in place.

---

## 13. When something is off

* `ida_kernwin.rosetta_doctor()` first.
* `tests/rsp_probe.py --port 1239 --pid <pid>` measures the stub packet by
  packet; if `vAttach` takes ~0.3 s and 64 KB reads ~0.3 s, the stub is fine and
  the problem is elsewhere.
* [TROUBLESHOOTING.md](TROUBLESHOOTING.md) maps symptoms to causes.

---

## Limitations worth knowing

* There is **no entry in IDA's debugger list** — this is an attach helper on top
  of Remote GDB, not a debugger backend (see [DESIGN.md](DESIGN.md) for why).
* Only `x86_64` targets are handled; the actions are not intercepted for native
  arm64 databases or programs without an `x86_64` slice.
* The program must run at the database's image base (the bundled launcher does
  that; a plain launch usually does not).
* The plugin relies on IDA's action names `ProcessStart` / `ProcessAttach` when
  interception is enabled; see [COMPATIBILITY.md](COMPATIBILITY.md) if an IDA
  update changes them.
