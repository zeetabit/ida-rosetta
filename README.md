# ida-rosetta

[![ci](https://github.com/zeetabit/ida-rosetta/actions/workflows/ci.yml/badge.svg)](https://github.com/zeetabit/ida-rosetta/actions/workflows/ci.yml)

**Debug x86_64 (Rosetta) processes with IDA Pro on Apple Silicon.**

IDA 9.x (arm64) cannot debug a translated x86_64 process: its macOS debugger is
ARM-only, and Apple's native `debugserver` refuses translated targets. Apple's
supported controller is `/usr/libexec/rosetta/debugserver`, a GDB RSP stub.
This plugin drives IDA's **Remote GDB** backend against that stub, so after the
attach everything (registers, memory, breakpoints, stepping, modules) is the
normal IDA debugger.

> **Status:** 0.1.0 — early, works on IDA 9.x arm64 / macOS 26.x. Not a debugger
> backend: it automates the attach that IDA cannot do by itself.

## Why

| piece | reality |
|---|---|
| `arm_mac_user.dylib` | "Local ARM Mac OS debugger" — arm64 targets only |
| `mac_user.dylib` (x86_64) | cannot be loaded by the arm64 IDA |
| native `debugserver` | *"Trying to attach to a translated process with the native debugserver, exiting…"* |
| `/usr/libexec/rosetta/debugserver` | arm64e GDB stub — the only way in |
| GDB `vFile` | **not implemented** by that stub → IDA cannot *start* a process through it, only *attach* |

LLDB does the same thing internally (it spawns the Rosetta stub for translated
processes). This project is the same policy, applied to IDA.

## How it works

```
IDA (arm64)                                   translated x86_64 process
┌──────────────────────────────┐              ┌────────────────────────┐
│ plugin/rosetta.py            │              │  program (x86_64)      │
│  F9 / Attach to process      │              │  __TEXT @ 0x100000000  │
│  → find pid, check base      │              └───────────▲────────────┘
│  → idle stub → attach        │                          │
│  → database breakpoints      │              ┌───────────┴────────────┐
│  → continue                  │  GDB RSP     │ rosetta/debugserver    │
└──────────────┬───────────────┘  127.0.0.1   │ (arm64e, idle, vAttach)│
               └──────────────────:1239──────►└────────────────────────┘
```

1. The target is started with **ASLR disabled** so it loads at the database's
   image base (`0x100000000` for a default PIE). The bundled `noaslr` launcher
   does this with `posix_spawn` + `POSIX_SPAWN_DISABLE_ASLR`.
2. The plugin finds the process, spawns an **idle** Rosetta stub, and calls
   `ida_dbg.attach_process(pid, -1)`.
3. IDA applies the database's breakpoints and continues.

## Requirements

* IDA Pro 9.x, **arm64** build, on Apple Silicon
* macOS with Rosetta (the stub is present on 11+)
* `clang` from the Xcode command line tools — used **once** to build the
  launcher, and again whenever the plugin version or launcher source changes
* one-time IDA config override (below)

## Install

```bash
git clone https://github.com/zeetabit/ida-rosetta.git
ln -s "$PWD/ida-rosetta/plugin/rosetta.py" ~/.idapro/plugins/rosetta.py
```

Start IDA. The Output window should show:

```
[rosetta] v0.2.0 installed: F9 / Attach to process -> Rosetta attach (port 1239)
[rosetta] note: dbg_gdb.cfg lacks the Rosetta register map; run ...
```

Then, in the IDA console, once:

```python
ida_kernwin.rosetta_install_cfg()   # writes $IDAUSR/cfg/dbg_gdb.cfg
```

and restart IDA. (This adds the `com.apple.debugserver.x86_64` register feature
to a *user-level override*; the app bundle is never modified and no `sudo` is
needed. Running the tool `tools/ida_gdb_cfg.py` does the same for a single
file.)

## Use

`Debugger → Rosetta` gives you:

| entry | what it does |
|---|---|
| **pick and start…** | dialog with program path, arguments, working directory and environment (`KEY=VALUE …`); starts it with the bundled launcher, then attaches |
| **pick program…** | only remembers the program for this database |
| **attach by process…** | filterable list of running processes (PID / name / command); attaches to the selected one |
| **attach to running target** | attaches to the already-selected program |
| **doctor / prerequisites** | version, launcher stamp, stub path, config-patch state, image bases |
| **rebuild launcher** | forces a rebuild from the embedded source |

`Edit → Plugins → "Rosetta debug"` runs **pick and start…** as well.

Or start the target yourself and press **F9**:

```bash
~/.idapro/plugins/ida-rosetta/noaslr /path/to/program
```

Console helpers:

```python
ida_kernwin.rosetta_start()         # the pick-and-start dialog
ida_kernwin.rosetta_attach_pid()    # process chooser
ida_kernwin.rosetta_attach()        # attach to the current target
ida_kernwin.rosetta_pick()          # choose another program
ida_kernwin.rosetta_doctor()        # compatibility / upgrade report
ida_kernwin.rosetta_rebuild()       # force launcher rebuild
ida_kernwin.rosetta_go()            # continue
```

## Upgrading (and rebuilding)

The launcher is **not** shipped as a binary. Its C source is embedded in the
plugin; on first use the plugin writes it to

```
~/.idapro/plugins/ida-rosetta/noaslr.c
```

and compiles a universal (arm64 + x86_64) `noaslr` next to it.

Every build is stamped in `launcher.json` with the **plugin version** and a
**SHA-256 of the embedded source**. On startup/use:

* version or source changed → rebuild automatically;
* the new binary is built to `noaslr.build` and swapped in atomically
  (`os.replace`), so a failed compile never breaks a working launcher;
* if the rebuild fails, the previous binary is kept and a warning is logged;
* force a rebuild at any time with `ida_kernwin.rosetta_rebuild()`, or by
  deleting `~/.idapro/plugins/ida-rosetta/`.

After an **IDA upgrade**:

1. IDA may replace `cfg/dbg_gdb.cfg`. Run `ida_kernwin.rosetta_doctor()`; if
   `roslyn map present` is `False`, run `ida_kernwin.rosetta_install_cfg()`
   again and restart IDA.
2. If the plugin's hook stops firing, check that the actions are still named
   `ProcessStart` / `ProcessAttach` (see `docs/COMPATIBILITY.md`).
3. `settings.json` is schema-versioned and migrates automatically.

## Files and state

```
~/.idapro/plugins/rosetta.py                  the plugin (symlink/copy)
~/.idapro/plugins/ida-rosetta/noaslr          built launcher (universal)
~/.idapro/plugins/ida-rosetta/noaslr.c        embedded source, written on build
~/.idapro/plugins/ida-rosetta/launcher.json   version + source hash stamp
~/.idapro/plugins/ida-rosetta/settings.json   per-idb target, args, break_off
~/.idapro/plugins/ida-rosetta/stub.log        stub stderr
$IDAUSR/cfg/dbg_gdb.cfg                       patched copy (config override)
```

## Limitations

* **Attach only.** The stub has no `vFile`, so IDA's normal "Start process"
  cannot be used; the plugin intercepts `ProcessStart`/`ProcessAttach` and
  attaches instead. It does not appear in `Debugger → Switch debugger…`.
* The target must run at the database's image base (use the launcher).
* Depends on the IDA action names above and on `ida_dbg`'s API.
* One stub port (`1239`) per IDA instance.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Start with
`ida_kernwin.rosetta_doctor()`, and if attach feels slow run

```bash
tests/rsp_probe.py --port 1239 --pid <pid>
```

## Design notes

[docs/DESIGN.md](docs/DESIGN.md) covers the evidence, the measured stub
behaviour, why this is an action hook instead of a native `debugger_t` module,
and what a native module would cost. [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)
has the version matrix and the post-upgrade checklist.

## License

MIT — see [LICENSE](LICENSE). Not affiliated with Hex-Rays or Apple.
