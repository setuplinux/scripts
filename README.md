# Available Scripts

These helper scripts target Ubuntu 24.04 Server in my personal lab environment. They may help you too, but they come with **no warranty**—review the contents and use at your own risk.

Quick index:
- `cluster_tui.py` — curses TUI for cluster checks/repair with logging and tutorial sidebar.
- `tmux-three-way.sh` — open three even panes, SSH to the hosts you pass, and mirror input.

## Local development preferences

`local_dev_preferences.json` pins the default palette, layout, logging format, and stdlib-only dependency posture to match `cluster_tui.py`. Use it as the baseline when building new TUIs or running existing ones in a dev-only setting so the look, logs, and coding assumptions stay consistent.

## cluster_tui.py

Curses-based cluster health dashboard and repair helper. It runs SSH, storage, and cluster-service checks for the hosts listed at the top of the file, lets you trigger repairs per host or across the entire cluster, records logs for each action, and automatically re-runs the check suite after repairs complete so you can verify status without leaving the UI.

### Highlights
- Header shows `Cluster TUI vYYYY.MM.DD | Log: /full/path/cluster_tui-YYYYMMDD.log` so you always know which build and log file are live. The title line is colorized on capable terminals with a spacer row under it for readability.
- Split panes: the left menu lists hosts, datastore helpers, and global actions. The right pane shows recent actions plus a copy/paste-friendly tutorial block that spells out the exact SSH commands each action will run and why.
- Logs for every check/repair are appended to the date-based log file next to the script and summarized inline for the selected host.

### Quick start
```bash
# Run against explicit host list.
python3 cluster_tui.py e1,10.10.10.5 e2,10.10.10.6 e3,10.10.10.7

# Or edit DEFAULT_HOSTS_LINE near the top of the script (empty by default) with
# a single line of hostnames/IPs, optionally as "name,ip" pairs if you care about
# display name vs target.
# and run without arguments.
python3 cluster_tui.py

# Confirm the file you plan to commit/publish.
ls -l cluster_tui.py
realpath cluster_tui.py

# Optional: set defaults if you SSH as a non-root sudo user.
sed -i 's/^SSH_USER = "root"/SSH_USER = "keith"/' cluster_tui.py
# Either bake in SSH_PASSWORD = "..." or press p inside the TUI to enter it once.
# Password flows require sshpass on the local machine; if policy forbids extra packages,
# stick to SSH keys (the UI will refuse to store a password and remind you).
```

During the session you can:
- Use ←/→ to switch focus, Tab or `[`/`]` to cycle top-level menus, and Enter to drill into actions.
- Press `p` once to supply an SSH password (requires `sshpass`; otherwise the app stays in key-only mode and tells you why). Without a password the app runs SSH with `BatchMode=yes` so failures show up immediately instead of hanging the terminal.
- There is an explicit “Exit (q)” entry in the left pane if you prefer navigating to a quit option instead of pressing `q`.
- Jump into the tutorial panel to copy the exact SSH/system commands that “Check host”, “Repair host”, or “Repair all” will execute. This doubles as documentation for your runbooks or GitHub issues.

The script expects SSH access as root plus the utilities invoked in the check/repair steps (pcs, iscsiadm, multipath, systemctl, etc.). Host key prompts are suppressed to avoid curses glitches, so only run this in trusted lab networks.

## tmux-three-way.sh

Launches a tmux session with three even horizontal panes, SSHs to each host, and enables synchronized input so the same commands run everywhere.

Usage:
```bash
./tmux-three-way.sh e1 e2 e3
```
- Host arguments accept bare names or full `user@host`; when no user is given it prepends `root@`.
- Session name is fixed to `three-way`; if it already exists you can attach to it or kill and recreate it.
- Requires tmux and SSH access to the targets; handles window layout and attaches automatically.
