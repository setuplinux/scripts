# Available Scripts

These helper scripts come with **no warranty**—review the contents and use at your own risk. See each script's documentation for its requirements and supported scope.

Quick index:
- [`nodepilot.py`](nodepilot.py) — **NodePilot**, a single-file, standard-library host companion with a read-only live TUI for system information, diagnostics, and command help. [Documentation](NODEPILOT.md).
- `tmux-three-way.sh` — open three even panes, SSH to the hosts you pass, and mirror input.

## NodePilot — quick start for POCs

SSH into the **VME host** (not the Manager appliance) using your approved administrator account. In a writable directory, copy and paste:

```bash
curl -fL https://raw.githubusercontent.com/setuplinux/scripts/main/nodepilot.py -o nodepilot.py && python3 nodepilot.py
```

This downloads the latest script and starts its terminal interface only if the download succeeds. It replaces any `nodepilot.py` in the current directory; review downloaded code according to your site's policy before running it.

- **No installer or pip packages.** Requires existing Python 3.10+, its `curses` module, and `hvmcli` for live information. Catalog tested against `hvmcli 1.0.0`, build `20260930`; other builds may differ.
- **Read-only:** host/VM information, networking, storage, health and diagnostic logs. No configuration changes or repair actions.
- **Keys:** arrows + Enter to navigate, Esc to go back, Page Up/Down to scroll, `/` to search output, `r` to refresh, `q` to quit.
- **Run again:** `python3 nodepilot.py` — no further download needed.
- **No GitHub access from the host?** [Download the script](https://raw.githubusercontent.com/setuplinux/scripts/main/nodepilot.py) on an approved computer, copy it to the host, then run the same Python command.

Unofficial community tool, not an HPE-supported product. Use only with site approval. [Full NodePilot help and limitations](NODEPILOT.md).

## tmux-three-way.sh

Launches a tmux session with three even horizontal panes, SSHs to each host, and enables synchronized input so the same commands run everywhere.

Usage:
```bash
./tmux-three-way.sh e1 e2 e3
```
- Host arguments accept bare names or full `user@host`; when no user is given it prepends `root@`.
- Session name is fixed to `three-way`; if it already exists you can attach to it or kill and recreate it.
- Requires tmux and SSH access to the targets; handles window layout and attaches automatically.
