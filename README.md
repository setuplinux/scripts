# Available Scripts

These helper scripts target Ubuntu 24.04 Server in my personal lab environment. They may help you too, but they come with **no warranty**—review the contents and use at your own risk.

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

# Or edit DEFAULT_HOSTS_LINE near the top of the script (single line of hostnames/IPs,
# optionally as "name,ip" pairs if you care about display name vs target)
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

### GitHub / publishing checklist
1. `python3 -m py_compile cluster_tui.py` to sanity check syntax.
2. `git status -sb` to verify the files you want to publish (README, cluster_tui.py, logs ignored).
3. `git add cluster_tui.py README.md` (and anything else you changed).
4. `git commit -m "Describe the change"` followed by `git push origin main`.
5. Update the repository description or release notes on GitHub to mirror the header version shown inside the TUI.

## upterm-2404-installer.sh

Installer for the latest Upterm release tuned for Ubuntu 24.04+. It detects `amd64` vs `arm64`, validates prerequisites (`curl` or `wget`, `tar`, `install`), downloads the current GitHub release tarball, extracts it to a temp dir, and installs `/usr/local/bin/upterm`.

Usage:

```bash
sh upterm-2404-installer.sh
upterm --version
```

After installation you can start secure read-only sessions (e.g., `upterm host --read-only -- bash`) or restrict access via `--authorized-key`/`--github-user`. Adjust options as needed for your lab.
