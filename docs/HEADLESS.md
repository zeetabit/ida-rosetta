# Headless usage (`idat -A -S…`)

The plugin runs in IDA's text-mode binary too. Everything UI-specific (menus,
actions, dialogs, the F9 hook) is skipped automatically when
`ida_kernwin.is_idaq()` is false; the attach/start logic is exposed as a plain
function.

## What works

* delegate the built-in Remote GDB backend to the Rosetta stub,
* attach to a running x86_64 process (verified: `attach_process -> 1`),
* start a program yourself with the bundled launcher (no Terminal needed),
* add breakpoints, continue, pump debugger events, read registers,
* run inside `idat -A -S"script"` with no GUI at all.

## What does not

* There is no event loop in headless mode. The debugger is *not* pumped for you;
  the helper calls `wait_for_next_event()` internally until the process is
  queryable, and again while waiting for a stop.
* IDAPython's output is not reliably captured when stdout is redirected. Always
  write results to a file (`--json`).

## Usage

```bash
# attach to an already running program (started with ./noaslr)
idat -A -S"tools/rosetta_headless.py --pid $(pgrep -x FallingWhale) \
      --bp 0x100003c78 --run --wait 20 --regs rdi,rsi,rdx \
      --json /tmp/run.json" program.i64

# let the plugin start it (launcher + optional stdin feed)
idat -A -S"tools/rosetta_headless.py --target /path/to/program --start \
      --stdin /tmp/program.stdin --json /tmp/run.json" program.i64
```

Options:

| option | meaning |
|---|---|
| `--pid N` | attach to this PID (executable resolved via `vmmap`) |
| `--target PATH` | program to attach to / start |
| `--start` | spawn it with the bundled launcher instead of attaching |
| `--args`, `--cwd`, `--env` | used with `--start` (`env` = `KEY=VALUE …`) |
| `--stdin PATH` | file/FIFO fed to the started program |
| `--bp SPEC` | breakpoint to add after attaching (repeatable: `0x…`, `+0x…`, `rva:0x…`, IDA name, `App+0x…`) |
| `--run` | continue after attaching |
| `--wait SECONDS` | pump events for up to N seconds waiting for a stop |
| `--regs a,b,c` | read these registers at the stop |
| `--detach` | detach instead of leaving the session open |
| `--json PATH` | result file (default `/tmp/rosetta_headless.json`) |

The JSON contains `ok`, `error`, `pid`, `path`, `runtime_base`, `attach`
(return code), `breakpoints`, `rip`, `state`, `stop`, and `registers`.

## API

From any IDAPython context (headless or GUI):

```python
ida_kernwin.rosetta_headless(path="/path/prog", pid=None, start=False,
                             breakpoints=["compare_code", "+0x3c78"], run=True,
                             wait_timeout=20, registers=["rdi", "rsi"],
                             on_bpt=on_bpt, base=None)
```

Returns the same dict as the driver. `ida_kernwin.rosetta_detach()` closes the
session.

`on_bpt(ctx)` is called on a breakpoint hit. Return `"continue"` (or `True`) to
resume automatically; anything else leaves the process stopped. `ctx` exposes
`ea`, `tid`, `reg()`, `regs()`, `read()`, `read_str()`, `write()`,
`continue_now()` and `stop()`. While `rosetta_headless(..., wait_timeout=…)`
pumps events, auto-continues are handled and the loop keeps waiting for a real
stop.

`base=0x100000000` skips the `vmmap` probe when the target was started without
ASLR (the bundled launcher guarantees this). Combined with `pid=`, it keeps an
attach below IDA Assist's short cooperative script budget; without it, the
normal GUI path still verifies the runtime base with `vmmap`.

Generic target template: [`examples/generic_helper.py`](../examples/generic_helper.py).

## Caveats

* `idat` must finish its analysis before `-S` runs. On a fresh database this can
  take a while; if you kill it with `SIGKILL`, the database is left dirty and the
  next run may exit without executing the script. Delete the `.i64` (or let it
  close cleanly) instead.
* FIFO writes block when nothing is reading them; use a long-lived writer
  (`sleep 600 > fifo &`) if you script the input.
* The image base must still match the database (`noaslr`).
