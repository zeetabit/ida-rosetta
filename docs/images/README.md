# Screenshots

The README references four images. Capture them with **⌘⇧4**, then **Space**
(window mode), then click the window/menu; macOS saves to `~/Desktop`.
Move/rename them here and (optionally) downscale to ≤1600 px wide:

```bash
sips -Z 1600 ~/Desktop/menu.png --out docs/images/menu.png
```

| file | how to capture |
|---|---|
| `menu.png` | `Debugger → Rosetta` **open** (keep the submenu expanded), then ⌘⇧4 + Space + click the menu. Shows the six entries and the checkable *Use for F9 / Attach to process*. |
| `start-dialog.png` | `Debugger → Rosetta → Pick and start…`, then ⌘⇧4 + Space + click the dialog. Fill something plausible first (path, `-v`, a working dir). Press **Cancel** after capturing. |
| `process-chooser.png` | `Debugger → Rosetta → Attach by process…`, type a fragment (e.g. `Fall`) in the chooser's search box, capture the window, then cancel. |
| `output-log.png` | The IDA **Output** window after a session: `Debugger → Rosetta → Attach to running target`, let it attach, then capture the Output pane. It shows `[rosetta] v… installed`, `attach_process(pid=…) -> 1 after …s`, and the attach notification. |

Notes:

* The start dialog's path field will show your real path (e.g.
  `/Users/<you>/…`). Crop it or type a neutral path (`/path/to/program`) before
  capturing if you prefer not to publish it.
* Any screenshot is fine as a plain full-window grab; no annotations needed.
