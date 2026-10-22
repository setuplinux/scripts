# NodePilot

A single-file host administration companion.

An **unofficial, single-file helper** for HPE VM Essentials. The curses TUI provides curated live read-only views; the loopback web UI and text catalog remain browse/preview-only. This is not an HPE product and does not replace vendor documentation.

## Safety boundary

The live TUI can execute only the literal argv entries in `LIVE_COMMANDS`:

- VM inventory: `vm list --details`
- Node: `node list`, `node show-config`
- Interfaces and networking: `interfaces list`, `network list`
- Hardware: `hardware cpu|memory|pci|bootvolume list`
- Installed software: `software list`
- virtSwitch: `virtswitch list`, `virtswitch status`, and `virtswitch show --virtswitch-name <validated-name>`
- Storage: pool list, iSCSI session/multipath views, FC port/multipath views, and multipath status/validation
- Cluster: status and node list
- Health: one-shot `health check`
- Diagnostics: non-live node/cluster/Morpheus-agent logs and the latest 100 warning-or-higher node events

There are no configure, update, deploy, VM power, host power, rescan, apply, or automatic watch actions. The runner uses `subprocess.Popen` with an argv list and `shell=False`, empty stdin, a restricted environment, a 15-second timeout, and a 256 KiB output ceiling. It kills a command at either bound. Terminal escape/control sequences are stripped before display, and common bearer tokens, API keys, passwords, secrets, and URL passwords are masked on a best-effort basis.

The web server has **no execution endpoint**. Its command previews are inert text.

## Files

- `nodepilot.py` — the one-file Python standard-library distributable.
- `tests/test_nodepilot.py` — unit, HTTP integration, runner safety, and real PTY curses tests.

The script embeds sanitized help for all 101 advertised non-help command/action paths from `hvmcli 1.0.0 (build 20260930)`. It does not need the source catalog at runtime.

## Requirements

- Python 3.10 or newer; Python 3.13 tested.
- A terminal with Python's standard `curses` module for the TUI.
- `hvmcli` in `PATH` for live views. If it is absent, the TUI displays a readable error and remains usable as a help browser.
- A modern browser for the optional loopback web UI.

No third-party Python dependencies are used.

## Quick download and run

On the VME host, in a writable directory:

```bash
curl -fL https://raw.githubusercontent.com/setuplinux/scripts/main/nodepilot.py -o nodepilot.py && python3 nodepilot.py tui
```

This replaces the local `nodepilot.py` and launches only after a successful download. Follow your site's code-review and execution policy. For an offline host, download on an approved computer and copy the single file over. No installer is required. Next time, run `python3 nodepilot.py tui`.

## Run

```bash
cd scripts

# Live read-only curses UI (default)
python3 nodepilot.py
python3 nodepilot.py tui

# Browse-only loopback web UI
python3 nodepilot.py web
python3 nodepilot.py web --open-browser

# Browse-only text catalog
python3 nodepilot.py list
python3 nodepilot.py search "storage --multipath"
python3 nodepilot.py show "hvmcli vm stop"

# Inert preview text; never executed
python3 nodepilot.py preview "hvmcli vm stop" --args='--name "demo vm" --force'
```

### TUI keys

- `Up`/`Down` or `j`/`k`: move the highlighted selection.
- `Enter`/`Right`: open a submenu or run the selected read-only view.
- `Esc`/`Left`: return to the parent menu; at the main menu, exit.
- `r`: refresh the last selected live view.
- `PageUp`/`PageDown`: scroll output.
- `/`: search within current output; `n` selects the next match.
- `q`: exit.

The **Command help browser** submenu is browse/preview-only. Its `p` key creates inert previews exactly as the text `preview` mode does.

## Web safety controls

- Always binds to IPv4 loopback (`127.0.0.1`), including when `localhost` is selected.
- Requires a fresh random token on every HTML/API request.
- Rejects untrusted `Host` and `Origin` values.
- Supports only `GET` and `HEAD`, and only `/` and `/api/catalog`.
- Has no execution route and emits no wildcard CORS header.
- Sends restrictive CSP, framing, MIME-sniffing, referrer, same-origin resource, and no-store headers.
- Inserts catalog content with DOM `textContent`, not `innerHTML`.

## Catalog provenance

The embedded catalog was generated from successful installed-help results for the recorded build.

Only successful command paths and help stdout were used. Host addresses, timestamps, invocations, return codes, stderr, collector paths, example sections, IPv4 values, and `private filesystem` paths were excluded or redacted. The live allowlist was manually limited to the documented read-only forms in that catalog.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile nodepilot.py tests/test_nodepilot.py
```

Tests cover catalog completeness and sanitization, browse-only web controls, allowlist contents, unknown-command rejection, missing `hvmcli`, process timeout/kill, output truncation, secret masking, menu state, output search/scroll, and real PTY Enter/Esc/q navigation.

## Limitations

- The allowlist is fixed to installed help build `20260930`; a different `hvmcli` build may format output differently or reject an argv.
- Three documented log commands expose only `--live` as an option. The helper deliberately omits `--live`; because the installed help documents no line-count flag for them, safety is enforced by the runner's timeout and byte ceiling rather than an invented flag. Node events use documented `--lines 100 --priority warning`.
- Secret masking is defensive and best-effort; arbitrary sensitive text with an unknown shape may remain visible. Treat diagnostic output as sensitive.
- `virtswitch show` requires a name. The helper accepts only a short validated identifier and appends it as one argv element; it never interpolates shell text.
- A timed-out process is killed, but underlying work already performed by `hvmcli` cannot be rolled back. Only commands documented as read-only are allowlisted.
- Narrow terminals below 60x12 show a resize message rather than a broken layout.
- Seven nested source-catalog paths repeat ancestor help because installed help did not provide distinct leaf text.
