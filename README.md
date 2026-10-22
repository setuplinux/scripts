# Available Scripts

These helper scripts come with **no warranty**—review the contents and use at your own risk. See each script's documentation for its requirements and supported scope.

Quick index:
- [`nodepilot.py`](nodepilot.py) — **NodePilot**, a single-file, standard-library host companion: read-only live TUI with system information and diagnostics, plus a browse-only web command catalog. [Documentation](NODEPILOT.md).
- `tmux-three-way.sh` — open three even panes, SSH to the hosts you pass, and mirror input.

## tmux-three-way.sh

Launches a tmux session with three even horizontal panes, SSHs to each host, and enables synchronized input so the same commands run everywhere.

Usage:
```bash
./tmux-three-way.sh e1 e2 e3
```
- Host arguments accept bare names or full `user@host`; when no user is given it prepends `root@`.
- Session name is fixed to `three-way`; if it already exists you can attach to it or kill and recreate it.
- Requires tmux and SSH access to the targets; handles window layout and attaches automatically.
