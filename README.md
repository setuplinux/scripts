# Available Scripts

These helper scripts target Ubuntu 24.04 Server in my personal lab environment. They may help you too, but they come with **no warranty**—review the contents and use at your own risk.

## cluster_tui.py

Curses-based cluster health dashboard and repair helper. It runs SSH, storage, and cluster-service checks for the hosts listed at the top of the file, lets you trigger repairs per host or across the entire cluster, records logs for each action, and automatically re-runs the check suite after repairs complete so you can verify status without leaving the UI.

Usage:

```bash
python3 cluster_tui.py
```

Requires passwordless SSH access as root plus the system utilities invoked in the check/repair steps (pcs, iscsiadm, systemctl, etc.).

## upterm-2404-installer.sh

Installer for the latest Upterm release tuned for Ubuntu 24.04+. It detects `amd64` vs `arm64`, validates prerequisites (`curl` or `wget`, `tar`, `install`), downloads the current GitHub release tarball, extracts it to a temp dir, and installs `/usr/local/bin/upterm`.

Usage:

```bash
sh upterm-2404-installer.sh
upterm --version
```

After installation you can start secure read-only sessions (e.g., `upterm host --read-only -- bash`) or restrict access via `--authorized-key`/`--github-user`. Adjust options as needed for your lab.

