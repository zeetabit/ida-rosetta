# ida-rosetta -- debug x86_64 (Rosetta) processes with IDA Pro on Apple Silicon
#
# Why this exists
# ---------------
# On Apple Silicon, an x86_64 Mach-O runs as a *translated* process. Apple's
# native debugserver refuses those ("Trying to attach to a translated process
# with the native debugserver, exiting..."), and IDA 9.x only ships an ARM macOS
# debugger (arm_mac_user.dylib) -- its x86_64 counterpart cannot be loaded by an
# arm64 IDA. The supported controller is /usr/libexec/rosetta/debugserver, a GDB
# RSP stub. IDA's Remote GDB backend can drive it, but the stub implements no
# "vFile", so IDA cannot *start* a process through it -- only *attach*.
#
# This plugin does exactly what LLDB does internally: find the translated
# process, spawn an idle Rosetta stub, and attach IDA's Remote GDB backend to it.
# After that, registers, memory, breakpoints, stepping and modules are all
# handled by IDA's normal debugger engine.
#
# Usage
# -----
#   Debugger > Rosetta:
#     "pick and start..."     program + arguments + cwd + environment; starts it
#                              with the bundled launcher and attaches
#     "pick program..."       only remembers the program for this idb
#     "attach by process..."  filterable process list (pid/name/command)
#     "attach to running target", "doctor / prerequisites", "rebuild launcher"
#
#   Start the program yourself instead with:
#          ~/.idapro/plugins/ida-rosetta/noaslr [args] /path/to/program
#   then press F9 (or Debugger > "Attach to process...").
#
# Requirements
# ------------
#   * IDA Pro 9.x, arm64 build, macOS on Apple Silicon
#   * cfg/dbg_gdb.cfg must know the stub's "com.apple.debugserver.x86_64"
#     register feature. The plugin detects this; run
#         ida_kernwin.rosetta_install_cfg()
#     once (it writes an override into $IDAUSR/cfg/) and restart IDA.
#   * clang (Xcode command line tools) for the launcher; only on first use
#     and whenever the plugin version / embedded source changes.

__version__ = "0.4.0"

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import time

import idaapi
import ida_kernwin
import ida_dbg

try:
    import ida_diskio
except Exception:                                    # pragma: no cover
    ida_diskio = None

STUB_CANDIDATES = (
    "/usr/libexec/rosetta/debugserver",
    "/Library/Apple/usr/libexec/oah/debugserver",
)
PORT = 1239

# "never"  -> you start the program yourself with the bundled launcher
# "always" -> F9 starts it (or restarts it under the launcher) automatically
LAUNCH_MODE = "never"

# Source of the launcher. Compiled on first use into
#   <user idadir>/plugins/ida-rosetta/noaslr
# and rebuilt automatically when this text changes.
NOASLR_C = r'''
// noaslr -- run a program with ASLR disabled (POSIX_SPAWN_DISABLE_ASLR)
//
// usage: noaslr [-q] [-p pidfile] program [args...]
//   -q, --quiet       do not print the child pid
//   -p, --pidfile F   also write the child pid to F
//   -v, --version
//   -h, --help
//
// Works for any Mach-O executable (x86_64 runs under Rosetta on Apple Silicon).
// Exits with the child's exit status and forwards SIGINT/SIGTERM/SIGHUP to it.

#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#ifndef POSIX_SPAWN_DISABLE_ASLR
#define POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

static pid_t g_child = -1;

static void forward(int sig) {
    if (g_child > 0) kill(g_child, sig);
}

static void usage(FILE *f, const char *prog) {
    fprintf(f, "usage: %s [-q] [-p pidfile] program [args...]\n"
               "run 'program' with ASLR disabled (POSIX_SPAWN_DISABLE_ASLR)\n",
            prog);
}

int main(int argc, char **argv) {
    int quiet = 0;
    const char *pidfile = NULL;
    int i = 1;

    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
        if (a[0] != '-' || !strcmp(a, "-")) break;
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout, argv[0]); return 0; }
        if (!strcmp(a, "-v") || !strcmp(a, "--version")) { printf("noaslr 2.0\n"); return 0; }
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) { quiet = 1; continue; }
        if (!strcmp(a, "-p") || !strcmp(a, "--pidfile")) {
            if (i + 1 >= argc) { usage(stderr, argv[0]); return 2; }
            pidfile = argv[++i];
            continue;
        }
        fprintf(stderr, "%s: unknown option %s\n", argv[0], a);
        usage(stderr, argv[0]);
        return 2;
    }
    if (i >= argc) { usage(stderr, argv[0]); return 2; }

    posix_spawnattr_t attr;
    int r = posix_spawnattr_init(&attr);
    if (r) { fprintf(stderr, "noaslr: posix_spawnattr_init: %s\n", strerror(r)); return 1; }
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_DISABLE_ASLR);

    pid_t pid;
    r = posix_spawnp(&pid, argv[i], NULL, &attr, &argv[i], environ);
    posix_spawnattr_destroy(&attr);
    if (r) { fprintf(stderr, "noaslr: %s: %s\n", argv[i], strerror(r)); return 1; }

    g_child = pid;
    if (!quiet) { printf("%d\n", (int)pid); fflush(stdout); }
    if (pidfile) {
        FILE *f = fopen(pidfile, "w");
        if (f) { fprintf(f, "%d\n", (int)pid); fclose(f); }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = forward;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 0;
}
'''

_STATE = {"t0": 0.0, "pid": 0, "base": 0, "notified_off": False}
_CFG_OK = None


# ----------------------------------------------------------------- helpers

def _msg(text):
    ida_kernwin.msg("[rosetta] %s\n" % text)


def _hint(text):
    _msg(text)
    try:
        ida_kernwin.beep()
    except Exception:
        pass


def _run(args, timeout=20):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout)
    except Exception as exc:
        _msg("command failed %r: %r" % (args, exc))
        return None


def _user_dir():
    if ida_diskio is not None:
        try:
            return ida_diskio.get_user_idadir()
        except Exception:
            pass
    return os.path.join(os.path.expanduser("~"), ".idapro")


DATA_DIR = os.path.join(_user_dir(), "plugins", "ida-rosetta")
LAUNCHER = os.path.join(DATA_DIR, "noaslr")
LAUNCHER_STATE = os.path.join(DATA_DIR, "launcher.json")
SETTINGS = os.path.join(DATA_DIR, "settings.json")
STUB_LOG = os.path.join(DATA_DIR, "stub.log")

_SETTINGS_SCHEMA = 1


def _read_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception as exc:
        _msg("could not write %s: %r" % (path, exc))
        return False


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------- launcher

def _find_cc():
    for cand in ("/usr/bin/clang", "/usr/bin/cc"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("clang") or shutil.which("cc")


def _build_launcher(src_hash):
    os.makedirs(DATA_DIR, exist_ok=True)
    src = os.path.join(DATA_DIR, "noaslr.c")
    try:
        with open(src, "w") as f:
            f.write(NOASLR_C)
    except Exception as exc:
        _msg("could not write %s: %r" % (src, exc))
        return False

    cc = _find_cc()
    if not cc:
        _hint("clang not found; install the Xcode command line tools\n"
              "    xcode-select --install\n"
              "or build launcher/noaslr.c yourself and place the binary at\n"
              "    %s" % LAUNCHER)
        return False

    tmp = LAUNCHER + ".build"
    variants = (
        ["-arch", "arm64", "-arch", "x86_64", "-mmacosx-version-min=11.0"],
        ["-arch", platform.machine(), "-mmacosx-version-min=11.0"],
        [],
    )
    for extra in variants:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        r = _run([cc, "-O2", "-Wall"] + extra + ["-o", tmp, src], timeout=120)
        if r is not None and r.returncode == 0 and os.path.isfile(tmp):
            try:
                os.chmod(tmp, 0o755)
                os.replace(tmp, LAUNCHER)          # atomic swap
            except OSError as exc:
                _msg("could not install launcher: %r" % (exc,))
                return False
            _write_json(LAUNCHER_STATE, {
                "plugin_version": __version__,
                "c_source_sha256": src_hash,
                "cc": cc,
                "arch_flags": extra,
                "built_at": int(time.time()),
            })
            _msg("built launcher %s (%s)" % (LAUNCHER, " ".join(extra) or "native"))
            return True
        err = (r.stderr.strip().splitlines()[-1] if r and r.stderr.strip() else "unknown error")
        _msg("launcher build variant failed (%s): %s" % (" ".join(extra) or "native", err))
    return False


def _launcher(force=False):
    """Path to the ASLR-disabling launcher, building/refreshing it if needed."""
    src_hash = _sha256_text(NOASLR_C)
    state = _read_json(LAUNCHER_STATE, {})
    fresh = (
        os.path.isfile(LAUNCHER)
        and os.access(LAUNCHER, os.X_OK)
        and state.get("c_source_sha256") == src_hash
    )
    if fresh and not force:
        if state.get("plugin_version") != __version__:
            # same launcher source: keep the binary, refresh the stamp only
            state["plugin_version"] = __version__
            _write_json(LAUNCHER_STATE, state)
        return LAUNCHER

    if not fresh:
        why = ("not built" if not os.path.isfile(LAUNCHER)
               else "embedded launcher source changed")
        _msg("launcher needs a (re)build: %s" % why)

    if _build_launcher(src_hash):
        return LAUNCHER

    if os.path.isfile(LAUNCHER) and os.access(LAUNCHER, os.X_OK):
        _hint("rebuild failed; falling back to the previously built launcher "
              "(v%s). Delete %s and retry to force a rebuild."
              % (state.get("plugin_version", "?"), LAUNCHER))
        return LAUNCHER
    return None


def rosetta_rebuild():
    """Force a launcher rebuild (menu/console helper)."""
    return _launcher(force=True) is not None


def _env_tokens(env_text):
    """Parse "K=V K2=V2" (spaces or newlines) into shell tokens."""
    text = (env_text or "").replace("\n", " ").strip()
    if not text:
        return []
    try:
        toks = shlex.split(text)
    except ValueError:
        return None
    return toks if all("=" in t for t in toks) else None


def _launch_cmd(path, args=None, env=None, cwd=None):
    entry = _settings()
    args = (entry.get("args") or "") if args is None else args
    env = (entry.get("env") or "") if env is None else env
    cwd = (entry.get("cwd") or "") if cwd is None else cwd
    args = args.strip()

    toks = _env_tokens(env)
    if toks is None:
        _msg("ignoring malformed environment string (need KEY=VALUE)")
        toks = []

    exe = _launcher()
    parts = []
    if toks:
        parts.append("env " + " ".join(shlex.quote(t) for t in toks))
    if exe:
        parts.append(shlex.quote(exe))
    parts.append(shlex.quote(path))
    if args:
        parts.append(args)
    cmd = " ".join(parts)
    if cwd.strip():
        cmd = "cd %s && %s" % (shlex.quote(cwd.strip()), cmd)
    return cmd


# ----------------------------------------------------------- IDA gdb config

def _cfg_paths():
    """(install cfg, effective cfg, user override) for dbg_gdb.cfg."""
    if ida_diskio is None:
        return "", "", ""
    try:
        inst = os.path.join(ida_diskio.idadir(ida_diskio.CFG_SUBDIR), "dbg_gdb.cfg")
        eff = ida_diskio.getsysfile("dbg_gdb.cfg", ida_diskio.CFG_SUBDIR) or inst
        usr = os.path.join(ida_diskio.get_user_idadir(), "cfg", "dbg_gdb.cfg")
        return inst, eff, usr
    except Exception:
        return "", "", ""


def _cfg_has_map(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return "com.apple.debugserver.x86_64" in f.read()
    except Exception:
        return False


def _cfg_ok():
    """True if the effective dbg_gdb.cfg knows the Rosetta stub's registers."""
    global _CFG_OK
    if _CFG_OK is None:
        _inst, eff, _usr = _cfg_paths()
        _CFG_OK = _cfg_has_map(eff) if eff else False
    return _CFG_OK


_FEATURE_BLOCK = '''    "com.apple.debugserver.x86_64":
    {
      "title": "General registers",
      "rename": { "rflags": "EFL" },
      "code_ptr": "rip",
      "stack_ptr": "rsp",
      "frame_ptr": "rbp",
      "data_ptr":
      [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
      ]
    },
'''


def _insert_feature_map(text):
    lines = text.splitlines(True)
    for i, line in enumerate(lines):
        if line.strip().rstrip(":").strip() == '"i386:x86-64"':
            for j in range(i + 1, min(i + 4, len(lines))):
                if lines[j].strip().startswith("{"):
                    return "".join(lines[:j + 1] + [_FEATURE_BLOCK] + lines[j + 1:])
    return None


def rosetta_install_cfg():
    """Write $IDAUSR/cfg/dbg_gdb.cfg with the Rosetta register map added."""
    global _CFG_OK
    inst, eff, usr = _cfg_paths()
    if not inst or not os.path.isfile(inst):
        _hint("cannot locate IDA's cfg/dbg_gdb.cfg")
        return False
    if _cfg_has_map(eff):
        _msg("dbg_gdb.cfg already has the Rosetta feature map (%s)" % eff)
        return True
    try:
        with open(inst, "r", errors="ignore") as f:
            text = f.read()
    except Exception as exc:
        _msg("could not read %s: %r" % (inst, exc))
        return False
    patched = text if "com.apple.debugserver.x86_64" in text else _insert_feature_map(text)
    if patched is None:
        _hint("could not find the \"i386:x86-64\" section in %s" % inst)
        return False
    try:
        os.makedirs(os.path.dirname(usr), exist_ok=True)
        with open(usr, "w") as f:
            f.write(patched)
    except Exception as exc:
        _msg("could not write %s: %r" % (usr, exc))
        return False
    _CFG_OK = None
    _hint("installed config override:\n    %s\nrestart IDA for it to take effect" % usr)
    return True


# ---------------------------------------------------------------- settings

def _idb_key():
    try:
        return idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
    except Exception:
        try:
            return idaapi.get_input_file_path() or ""
        except Exception:
            return ""


def _settings_all():
    data = _read_json(SETTINGS, {})
    if not isinstance(data, dict):
        data = {}
    if data.get("schema") != _SETTINGS_SCHEMA:
        # v0 layout: flat mapping <idb> -> {path, args, break_off}
        targets = {k: v for k, v in data.items()
                   if isinstance(v, dict) and "path" in v}
        data = {"schema": _SETTINGS_SCHEMA, "targets": targets}
    data.setdefault("targets", {})
    return data


def _settings():
    entry = _settings_all()["targets"].get(_idb_key())
    return dict(entry) if isinstance(entry, dict) else {}


def _ui_settings():
    ui = _settings_all().get("ui")
    return dict(ui) if isinstance(ui, dict) else {}


def _set_ui_setting(key, value):
    data = _settings_all()
    ui = data.get("ui")
    if not isinstance(ui, dict):
        ui = {}
    ui[key] = value
    data["ui"] = ui
    return _write_json(SETTINGS, data)


def _intercept_enabled():
    """Whether the plugin takes over F9 / Attach to process (default: no)."""
    return bool(_ui_settings().get("intercept_f9", False))


def _update_intercept_action():
    try:
        ida_kernwin.update_action_checked("rosetta:intercept",
                                          _intercept_enabled())
    except Exception:
        pass


def rosetta_toggle_intercept():
    """Enable/disable taking over F9 and Attach to process."""
    enabled = not _intercept_enabled()
    _set_ui_setting("intercept_f9", enabled)
    _update_intercept_action()
    _hint("F9 / Attach to process interception %s"
          % ("enabled" if enabled else "disabled (IDA handles them)"))
    return enabled


def _save_settings(entry):
    data = _settings_all()
    data["targets"][_idb_key()] = entry
    return _write_json(SETTINGS, data)


# ------------------------------------------------------------------ target

def _target_path():
    entry = _settings()
    path = (entry.get("path") or "").strip()
    if path and os.path.isfile(path):
        return path
    try:
        inp = idaapi.get_input_file_path() or ""
    except Exception:
        inp = ""
    if inp and os.path.isfile(inp):
        return inp
    return None


def _pick_target():
    entry = _settings()
    cur = entry.get("path") or _target_path() or os.path.expanduser("~")
    path = ida_kernwin.ask_file(False, cur, "Select the program to debug")
    if not path:
        _msg("cancelled")
        return None
    path = os.path.abspath(path)
    entry["path"] = path
    _save_settings(entry)
    _msg("target: %s (x86_64=%s)" % (path, _is_x86_64(path)))
    return path


def _pid_exe(pid):
    """Resolve (executable path, image base) of a pid through vmmap."""
    info = _vmmap(pid)
    for line in info.splitlines():
        if "__TEXT" not in line:
            continue
        for tok in reversed(line.split()):
            if tok.startswith("/"):
                return tok, _image_base(info, os.path.basename(tok))
    return None, None


class _ProcessChooser(ida_kernwin.Choose):
    """Modal process list; the chooser's search box filters by name."""

    def __init__(self, rows):
        ida_kernwin.Choose.__init__(
            self,
            "Select a process to attach",
            [["PID", 8], ["Name", 26], ["Command", 70]],
            flags=ida_kernwin.Choose.CH_MODAL,
        )
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]


def _process_rows():
    r = _run(["ps", "-axo", "pid=,comm=,command="], timeout=10)
    rows = []
    for line in (r.stdout.splitlines() if r else []):
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        pid, name = parts[0], parts[1]
        cmd = parts[2] if len(parts) > 2 else name
        rows.append([pid, name[:26], cmd[:70]])
    # real executables first, then the rest, each group alphabetically
    rows.sort(key=lambda row: (0 if "/" in row[2] else 1, row[1].lower()))
    return rows


def rosetta_attach_pid_value(pid):
    path, _base = _pid_exe(pid)
    if not path:
        _hint("cannot resolve the executable of pid %d" % pid)
        return False
    if not _is_x86_64(path):
        _hint("%s (pid %d) is not an x86_64 binary" % (path, pid))
        return False
    entry = _settings()
    entry["path"] = path
    _save_settings(entry)
    _msg("target from pid %d: %s" % (pid, path))
    return rosetta_attach("pid")


def rosetta_attach_pid():
    """Pick a running process from a filterable list and attach to it."""
    try:
        rows = _process_rows()
        if rows:
            idx = _ProcessChooser(rows).Show(True)
            if idx is None or idx < 0:
                _msg("cancelled")
                return False
            return rosetta_attach_pid_value(int(rows[idx][0]))
    except Exception as exc:
        _msg("process list failed (%r); falling back to a PID prompt" % (exc,))
    pid = ida_kernwin.ask_long(0, "PID to attach to:")
    if not pid:
        return False
    return rosetta_attach_pid_value(int(pid))


def rosetta_start_dialog():
    """Pick a program, edit args/cwd/env, start it, attach."""
    entry = _settings()
    path = entry.get("path") or _target_path() or os.path.expanduser("~")
    args = entry.get("args") or ""
    cwd = entry.get("cwd") or (os.path.dirname(path) if path else "")
    env = entry.get("env") or ""

    try:
        form = ida_kernwin.Form(
            r"""BUTTON YES* OK
BUTTON NO NONE
BUTTON CANCEL Cancel
Start the program and attach

<Program path:{iPath}>
<Arguments:{iArgs}>
<Working directory:{iDir}>
<Environment (KEY=VALUE ...):{iEnv}>
""",
            {
                "iPath": ida_kernwin.Form.FileInput(open=True),
                "iArgs": ida_kernwin.Form.StringInput(),
                "iDir": ida_kernwin.Form.DirInput(),
                "iEnv": ida_kernwin.Form.StringInput(),
            },
        )
        form.Compile()
        form.iPath.value = path
        form.iArgs.value = args
        form.iDir.value = cwd
        form.iEnv.value = env
        if form.Execute() != 1:
            form.Free()
            _msg("cancelled")
            return False
        path = form.iPath.value.strip()
        args = form.iArgs.value.strip()
        cwd = form.iDir.value.strip()
        env = form.iEnv.value.strip()
        form.Free()
    except Exception as exc:
        _msg("start dialog unavailable (%r); using the file picker" % (exc,))
        picked = ida_kernwin.ask_file(False, path, "Select the program to debug")
        if not picked:
            return False
        path, cwd = picked, os.path.dirname(picked)

    if not path or not os.path.isfile(path):
        _hint("no such file: %s" % path)
        return False
    if not _is_x86_64(path):
        _hint("%s has no x86_64 slice" % os.path.basename(path))
        return False
    if _env_tokens(env) is None:
        _hint("environment must be KEY=VALUE pairs")
        return False

    entry.update(path=path, args=args, cwd=cwd, env=env)
    _save_settings(entry)
    pid = _start_target(path, args=args, env=env, cwd=cwd)
    if pid is None:
        return False
    return rosetta_attach("start")


def _is_x86_64(path):
    r = _run(["lipo", "-archs", path], timeout=10)
    archs = (r.stdout if r and r.returncode == 0 else "").split()
    if not archs:
        r = _run(["file", "-b", path], timeout=10)
        archs = ((r.stdout if r else "") or "").split()
    return "x86_64" in archs or "x86_64h" in archs


def _should_intercept():
    path = _target_path()
    return bool(path) and _is_x86_64(path)


# ----------------------------------------------------------------- process

def _vmmap(pid):
    r = _run(["vmmap", str(pid)])
    return (r.stdout if r else "") or ""


def _image_base(vminfo, name):
    for line in vminfo.splitlines():
        if "__TEXT" in line and name in line:
            parts = line.split()
            if len(parts) > 1 and "-" in parts[1]:
                try:
                    return int(parts[1].split("-")[0], 16)
                except ValueError:
                    pass
    return None


def _find_process(path):
    name = os.path.basename(path)
    pids = []
    for selector in (["-x", name[:16]], ["-f", name]):
        r = _run(["pgrep"] + selector, timeout=5)
        for token in (r.stdout.split() if r else []):
            if token.isdigit():
                pids.append(int(token))
    for pid in sorted(set(pids), reverse=True):
        info = _vmmap(pid)
        if path in info or name in info:
            return pid, info
    return None, ""


def _resolve_stub():
    for cand in STUB_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def _listening(port):
    r = _run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"], timeout=5)
    return bool(r and r.stdout.strip())


def _ensure_stub():
    stub = _resolve_stub()
    if stub is None:
        _hint("no Rosetta debugserver found (looked for: %s)"
              % ", ".join(STUB_CANDIDATES))
        return False
    if _listening(PORT):
        return True
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        log = open(STUB_LOG, "ab")
        log.write(b"\n--- stub start %s ---\n" % time.ctime().encode())
        log.flush()
        subprocess.Popen(
            [stub, "-v", "127.0.0.1:%d" % PORT],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True,
        )
    except Exception as exc:
        _msg("could not start %s: %r" % (stub, exc))
        return False
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if _listening(PORT):
            return True
        time.sleep(0.05)
    _hint("%s did not listen on port %d (security software?)" % (stub, PORT))
    return False


def _start_target(path, args=None, env=None, cwd=None):
    cmd = _launch_cmd(path, args=args, env=env, cwd=cwd)
    script = 'tell application "Terminal" to do script "%s"' % (
        cmd.replace("\\", "\\\\").replace('"', '\\"'))
    r = _run(["osascript", "-e", script], timeout=15)
    if r is None or r.returncode != 0:
        _hint("could not start it automatically; run:\n    %s" % cmd)
        return None
    deadline = time.time() + 8.0
    while time.time() < deadline:
        pid, _info = _find_process(path)
        if pid:
            return pid
        time.sleep(0.1)
    return None


def rosetta_attach(reason=""):
    """Attach IDA's Remote GDB backend to the translated target."""
    t0 = time.time()
    if ida_dbg.is_debugger_on():
        _msg("debugger already active -- F9 continues")
        return False

    path = _target_path()
    if not path:
        _hint("no program selected: Edit > Plugins > \"Rosetta debug\"")
        return False
    name = os.path.basename(path)

    if not _cfg_ok():
        _hint("dbg_gdb.cfg lacks the com.apple.debugserver.x86_64 map.\n"
              "Run ida_kernwin.rosetta_install_cfg() once, then restart IDA.")
        return False

    pid, vminfo = _find_process(path)
    if pid is None:
        if LAUNCH_MODE != "always":
            _hint("%s is not running.\nStart it with:\n    %s\nthen press F9 again."
                  % (name, _launch_cmd(path)))
            return False
        pid = _start_target(path)
        if pid is None:
            return False
        _pid, vminfo = _find_process(path)

    base = _image_base(vminfo, name)
    if base is None:
        _hint("could not determine the image base of %s (pid %d)." % (name, pid))
        return False

    db_base = idaapi.get_imagebase()
    if base != db_base:
        if LAUNCH_MODE != "always":
            _hint("%s (pid %d) runs at 0x%x but the database uses 0x%x.\n"
                  "Restart it so the addresses match:\n    %s\n"
                  "(or set LAUNCH_MODE=\"always\" and press F9 again)"
                  % (name, pid, base, db_base, _launch_cmd(path)))
            return False
        _msg("%s has ASLR (0x%x); restarting it" % (name, base))
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception as exc:
            _msg("kill failed: %r" % (exc,))
        deadline = time.time() + 3.0
        while time.time() < deadline and _find_process(path)[0] == pid:
            time.sleep(0.05)
        pid = _start_target(path)
        if pid is None:
            return False
        _pid, vminfo = _find_process(path)
        base = _image_base(vminfo, name)
        if base != db_base:
            _hint("still not at 0x%x (base 0x%x)." % (db_base, base or 0))
            return False

    if not _ensure_stub():
        return False

    ida_dbg.set_remote_debugger("127.0.0.1", "", PORT)
    if not ida_dbg.load_debugger("gdb", True):
        _hint("could not load the Remote GDB debugger backend.")
        return False

    off = (_settings().get("break_off") or "").strip()
    if off:
        try:
            ea = db_base + int(off, 16)
        except ValueError:
            ea = None
            _msg("ignoring invalid break_off %r" % off)
        if ea and not ida_dbg.exist_bpt(ea):
            ok = ida_dbg.add_bpt(ea, 1, ida_dbg.BPT_BRK)
            _msg("breakpoint 0x%x -> %s" % (ea, ok))

    _STATE.update(t0=t0, pid=pid, base=db_base)

    # Direct attach. request_attach_process() only queues a request that IDA
    # services while a session already exists; from an action handler it would
    # never run. attach_process() performs the RSP handshake itself.
    rc = ida_dbg.attach_process(pid, -1)
    _msg("attach_process(pid=%d) -> %s after %.2fs" % (pid, rc, time.time() - t0))
    if rc != 1:
        _hint("attach failed (%s).\n"
              "- the stub must be idle (no --attach)\n"
              "- security software may be blocking it" % rc)
        return False

    try:
        ida_kernwin.jumpto(ida_dbg.get_reg_val("rip") or db_base)
    except Exception:
        pass
    ida_dbg.continue_process()
    _msg("running (total %.2fs); breakpoints come from the database"
         % (time.time() - t0))
    return True


# ----------------------------------------------------------------- helpers

def rosetta_go():
    if ida_dbg.is_debugger_on():
        ida_dbg.continue_process()


def rosetta_goto():
    if ida_dbg.is_debugger_on():
        try:
            ida_kernwin.jumpto(ida_dbg.get_reg_val("rip"))
        except Exception:
            pass


def rosetta_doctor():
    """Print a compatibility/upgrade report."""
    import idaapi as _idaapi
    inst, eff, usr = _cfg_paths()
    stub = _resolve_stub()
    path = _target_path()
    state = _read_json(LAUNCHER_STATE, {})
    pid, vminfo = _find_process(path) if path else (None, "")
    base = _image_base(vminfo, os.path.basename(path)) if pid else None

    rows = [
        ("plugin version", __version__),
        ("IDA version", "%s (%s)" % (_idaapi.get_kernel_version(), platform.machine())),
        ("user dir", _user_dir()),
        ("data dir", DATA_DIR),
        ("launcher", "%s [%s]" % (LAUNCHER, "ok" if os.access(LAUNCHER, os.X_OK) else "missing")),
        ("launcher state", "v%s, src %s" % (state.get("plugin_version", "?"),
                                           (state.get("c_source_sha256") or "?")[:12])),
        ("stub", stub or "NOT FOUND"),
        ("stub listening", str(_listening(PORT))),
        ("dbg_gdb.cfg (install)", inst or "?"),
        ("dbg_gdb.cfg (effective)", eff or "?"),
        ("rosetta map present", str(_cfg_ok())),
        ("user cfg override", usr if os.path.isfile(usr) else "(none)"),
        ("target", path or "(not selected)"),
        ("target x86_64", str(_is_x86_64(path)) if path else "?"),
        ("target pid", str(pid) if pid else "-"),
        ("target image base", hex(base) if base else "-"),
        ("ida image base", hex(_idaapi.get_imagebase())),
    ]
    width = max(len(k) for k, _ in rows)
    _msg("doctor")
    for k, v in rows:
        _msg("  %-*s : %s" % (width, k, v))
    return dict(rows)


# ------------------------------------------------------------- hooks/plugin

class _DbgHooks(ida_dbg.DBG_Hooks):
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        _msg("attach notification: pid=%d base=0x%x (t=%.2fs)"
             % (pid, base, time.time() - _STATE["t0"]))

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        _msg("process exited (code=%d)" % exit_code)

    def dbg_process_detach(self, pid, tid, ea):
        _msg("detached")


class _UiHooks(ida_kernwin.UI_Hooks):
    def preprocess_action(self, name):
        if name not in ("ProcessStart", "ProcessAttach"):
            return 0
        if not _intercept_enabled():
            if _should_intercept() and not _STATE.get("notified_off"):
                _STATE["notified_off"] = True
                _msg("F9/attach left to IDA: Rosetta interception is off "
                     "(enable it in Debugger > Rosetta)")
            return 0
        if ida_dbg.is_debugger_on():
            return 0
        if not _should_intercept():
            return 0
        _msg("%s -> Rosetta attach (%s)"
             % (name, os.path.basename(_target_path() or "")))
        try:
            rosetta_attach(name)
        except Exception as exc:
            _msg("attach failed: %r" % (exc,))
        return 1


class _Action(ida_kernwin.action_handler_t):
    def __init__(self, fn, name=None, checkable=False):
        ida_kernwin.action_handler_t.__init__(self)
        self.fn = fn
        self.name = name
        self.checkable = checkable

    def activate(self, ctx):
        try:
            self.fn()
        except Exception as exc:
            _msg("action failed: %r" % (exc,))
        if self.checkable:
            _update_intercept_action()
        return 1

    def update(self, ctx):
        if self.checkable and self.name:
            try:
                ida_kernwin.update_action_checked(self.name,
                                                  _intercept_enabled())
            except Exception:
                pass
        return ida_kernwin.AST_ENABLE_ALWAYS


_ACTION_FNS = {
    "start": rosetta_start_dialog,
    "intercept": rosetta_toggle_intercept,
    "pick": _pick_target,
    "pid": rosetta_attach_pid,
    "attach": rosetta_attach,
    "doctor": rosetta_doctor,
    "rebuild": rosetta_rebuild,
}

_ACTIONS = (
    ("rosetta:start", "Pick and start...", "start"),
    ("rosetta:pick", "Pick program...", "pick"),
    ("rosetta:attach_pid", "Attach by process...", "pid"),
    ("rosetta:attach", "Attach to running target", "attach"),
    ("rosetta:doctor", "Doctor / prerequisites", "doctor"),
    ("rosetta:rebuild", "Rebuild launcher", "rebuild"),
    ("rosetta:intercept", "Use for F9 / Attach to process", "intercept"),
)

# Two submenus carry the same actions: the primary one in the Debugger menu and
# a second one next to the plugin entry (Edit > Plugins).  A nested path only
# resolves for menus that already exist, so each menu must be created first.
_MENUS = (
    ("Rosetta", "Debugger/Start process"),             # primary
    ("RosettaPlugins", "Edit/Plugins/Rosetta debug"),  # next to the plugin entry
)


class RosettaPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Debug x86_64/Rosetta targets through the Rosetta GDB stub"
    help = ("Pick the program with the file picker; F9 then attaches Remote GDB "
            "through /usr/libexec/rosetta/debugserver.")
    wanted_name = "Rosetta debug"
    wanted_hotkey = ""

    def init(self):
        install()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        rosetta_start_dialog()

    def term(self):
        uninstall()


def install():
    for attr in ("_rosetta_ui_hook", "_rosetta_dbg_hook"):
        old = getattr(ida_kernwin, attr, None)
        if old is not None:
            try:
                old.unhook()
            except Exception:
                pass
            setattr(ida_kernwin, attr, None)

    ui = _UiHooks()
    if ui.hook():
        ida_kernwin._rosetta_ui_hook = ui
    else:
        _msg("could not install the UI hook")

    dbg = _DbgHooks()
    if dbg.hook():
        ida_kernwin._rosetta_dbg_hook = dbg
    else:
        _msg("could not install the debugger hook")

    _install_actions()

    ida_kernwin.rosetta_attach = rosetta_attach
    ida_kernwin.rosetta_pick = _pick_target
    ida_kernwin.rosetta_go = rosetta_go
    ida_kernwin.rosetta_goto = rosetta_goto
    ida_kernwin.rosetta_doctor = rosetta_doctor
    ida_kernwin.rosetta_rebuild = rosetta_rebuild
    ida_kernwin.rosetta_install_cfg = rosetta_install_cfg
    ida_kernwin.rosetta_start = rosetta_start_dialog
    ida_kernwin.rosetta_attach_pid = rosetta_attach_pid
    ida_kernwin.rosetta_toggle_intercept = rosetta_toggle_intercept

    _msg("v%s installed: menu Debugger > Rosetta; F9 interception is %s "
         "(port %d)" % (__version__,
                        "ON" if _intercept_enabled() else "OFF", PORT))
    if not _cfg_ok():
        _msg("note: dbg_gdb.cfg lacks the Rosetta register map; run "
             "ida_kernwin.rosetta_install_cfg() and restart IDA")


def _ensure_menus():
    """Create both submenus; return the paths actions should be attached to."""
    paths = []
    for index, (name, anchor) in enumerate(_MENUS):
        try:
            ida_kernwin.create_menu(name, "Rosetta", anchor)
        except Exception:
            pass
        if index == 0:
            # if the anchor could not be resolved, fall back to a top-level menu
            try:
                ida_kernwin.create_menu(name, "Rosetta")
            except Exception:
                pass
        paths.append(name + "/")
    return paths


def _install_actions():
    for desc, _handler in getattr(ida_kernwin, "_rosetta_actions", []):
        for path in getattr(ida_kernwin, "_rosetta_menus", []):
            try:
                ida_kernwin.detach_action_from_menu(path, desc.name)
            except Exception:
                pass
        try:
            ida_kernwin.unregister_action(desc.name)
        except Exception:
            pass

    menu_paths = _ensure_menus()
    installed = []
    for name, label, kind in _ACTIONS:
        checkable = kind == "intercept"
        handler = _Action(_ACTION_FNS[kind], name=name, checkable=checkable)
        desc = ida_kernwin.action_desc_t(name, label, handler)
        if not ida_kernwin.register_action(desc):
            _msg("could not register action %s" % name)
            continue
        if checkable:
            ida_kernwin.update_action_checkable(name, True)
            ida_kernwin.update_action_checked(name, _intercept_enabled())
        attached = False
        for path in menu_paths:
            try:
                attached |= bool(ida_kernwin.attach_action_to_menu(
                    path, name, ida_kernwin.SETMENU_APP))
            except Exception:
                pass
        if not attached:
            _msg("could not attach %s to any menu" % name)
        installed.append((desc, handler))
    ida_kernwin._rosetta_actions = installed
    ida_kernwin._rosetta_menus = menu_paths


def uninstall():
    for desc, _handler in getattr(ida_kernwin, "_rosetta_actions", []):
        for path in getattr(ida_kernwin, "_rosetta_menus", []):
            try:
                ida_kernwin.detach_action_from_menu(path, desc.name)
            except Exception:
                pass
        try:
            ida_kernwin.unregister_action(desc.name)
        except Exception:
            pass
    ida_kernwin._rosetta_actions = []
    for name, _anchor in _MENUS:
        try:
            ida_kernwin.delete_menu(name)
        except Exception:
            pass
    ida_kernwin._rosetta_menus = []
    for attr in ("_rosetta_ui_hook", "_rosetta_dbg_hook"):
        hook = getattr(ida_kernwin, attr, None)
        if hook is not None:
            try:
                hook.unhook()
            except Exception:
                pass
            setattr(ida_kernwin, attr, None)
    _msg("uninstalled")


def PLUGIN_ENTRY():
    return RosettaPlugin()


# Also usable via File > Script file... (no IDA restart required).
install()
