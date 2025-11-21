#!/usr/bin/env python3
"""VME maintenance TUI built on the cluster_tui health/repair helper."""

from __future__ import annotations

import curses
import json
import logging
import queue
import socket
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import time
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

# -------------------------------------------------------------------------
# SSH configuration
SSH_USER = "root"
SSH_PASSWORD = ""  # leave empty for key auth; password mode requires sshpass (not installed by default)
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Cluster recovery configuration (supports 3–10 nodes)
# Populate DEFAULT_HOSTS_LINE or CLI args; this list is advisory for validation.
CLUSTER_NODE_LIST: List[str] = []  # e.g. ["e1", "e2", "e3"]
RECOVERY_RESOURCE_LIST: List[str] = []  # e.g. ["dlm-clone", "gfs2-clone"]
TIME_DRIFT_THRESHOLD_SECS = 5

# Edit this single line with "host host" or "name,ip" tokens to change built-in hosts.
DEFAULT_HOSTS_LINE = ""

# CLUSTER_HOSTS populated at runtime
CLUSTER_HOSTS: List[Tuple[str, str]] = []
HOST_TARGETS: Dict[str, str] = {}

MENU_COLOR_PAIR = 5
TITLE_COLOR_PAIR = 6
MIN_GFS_NODES = 3

APP_VERSION = "v2025.02.18"

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_NAME = SCRIPT_PATH.stem
_DATE_STR = f"{datetime.now():%Y%m%d}"

# Menu structure for the VME console.
MAIN_MENU: List[Tuple[str, str, str]] = [
    ("cluster_health", "1) Cluster Health and Repair Wizard", "Run node checks, GFS/iSCSI repair, time sync, and summaries."),
    ("vm_inventory", "2) VM Inventory and Control", "List VMs, control VM manager, and stage per-VM actions."),
    ("datastore", "3) Datastore and Storage Overview", "View datastore status, health checks, and cleanup/export stubs."),
    ("hosts_config", "4) Hosts and Node Configuration", "Network, OS/patch status, drift, and service control placeholders."),
    ("logs_events", "5) Logs and Events", "Inspect recent logs, backup/snapshot checks, and export logs."),
    ("config_settings", "6) Configuration and Settings", "Defaults for time servers, alerts, TUI preferences, and help/about."),
    ("exit", "Q) Quit", "Exit the VME maintenance console."),
]

CLUSTER_HEALTH_MENU: List[Tuple[str, str, str]] = [
    ("node_status", "1.1) Node Status and Quorum", "Per-node status, corosync/pacemaker visibility, quorum notes."),
    ("gfs_repair", "1.2) GFS / iSCSI Resource Check and Repair", "Existing GFS/iSCSI repair wizard and controller cleanup."),
    ("time_ntp", "1.3) Time / NTP Check and Configure", "Time sync status and drift; configure time server across hosts."),
    ("health_summary", "1.4) Cluster Health Summary", "Aggregate status across nodes, storage, and time sync; exportable."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]

VM_INVENTORY_MENU: List[Tuple[str, str, str]] = [
    ("vm_list", "2.1) List VMs on all hosts", "Gather VM inventory per host with status."),
    ("vm_manager", "2.2) VM Manager Service", "Check/start/stop/restart the VM manager service."),
    ("vm_actions", "2.3) Individual VM Actions", "Select a VM and power on/off/reboot (stubs)."),
    ("vm_alerts", "2.4) VM Usage Alerts", "Placeholder for CPU/RAM or long-term powered-off alerts."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]

DATASTORE_MENU: List[Tuple[str, str, str]] = [
    ("ds_list", "3.1) List datastores via Verge or storage API", "List datastores (TODO: Verge/storage API calls)."),
    ("ds_health", "3.2) Datastore health checks", "Free/used thresholds and mount/health placeholders."),
    ("ds_cleanup", "3.3) Storage cleanup suggestions", "Placeholders for snapshots and nearly full datastores."),
    ("ds_export", "3.4) Export storage summary", "Export datastore summary to CSV/text."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]

HOST_CONFIG_MENU: List[Tuple[str, str, str]] = [
    ("net_health", "4.1) Network health", "Bond/VLAN/bridge status placeholders."),
    ("os_patch", "4.2) OS and patch status", "OS version, kernel, pending updates placeholders."),
    ("config_drift", "4.3) Configuration drift", "Compare nodes to baseline (TODO)."),
    ("service_control", "4.4) Service control", "List/start/stop/restart services on selected hosts."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]

LOGS_EVENTS_MENU: List[Tuple[str, str, str]] = [
    ("cluster_logs", "5.1) Recent cluster logs", "Pager for recent logs with simple filters."),
    ("backups", "5.2) Backup / snapshot checks", "Placeholder for backup job status and snapshot times."),
    ("export_logs", "5.3) Export logs", "Dump selected logs to a file."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]

CONFIG_SETTINGS_MENU: List[Tuple[str, str, str]] = [
    ("default_time_server", "6.1) Default time server", "Store/reuse time server for NTP ops."),
    ("alert_thresholds", "6.2) Alert thresholds", "Placeholder for disk/CPU/etc thresholds."),
    ("tui_prefs", "6.3) TUI preferences", "Preserve existing visuals; stub for future prefs."),
    ("help_about", "6.4) Help / About", "Short help and version info."),
    ("back_main", "Back to Main Menu", "Return to the top-level VME menu."),
]


def resolve_log_path() -> Path:
    """Pick a log file path that won't clobber prior runs."""
    base = SCRIPT_PATH.with_name(f"{SCRIPT_NAME}-{_DATE_STR}.log")
    if not base.exists():
        return base
    for idx in range(1, 100):
        candidate = SCRIPT_PATH.with_name(f"{SCRIPT_NAME}-{_DATE_STR}-{idx:02d}.log")
        if not candidate.exists():
            return candidate
    return base


LOG_FILE_PATH = resolve_log_path()
RECOVERY_LOG_PATH = LOG_FILE_PATH
LOG_FILE_DISPLAY = str(LOG_FILE_PATH)
CONFIG_FILE_PATH = SCRIPT_PATH.with_suffix(".config.json")
SSH_KNOWN_HOSTS_PATH = Path(tempfile.gettempdir()) / "cluster_tui_known_hosts"
try:
    SSH_KNOWN_HOSTS_PATH.touch(exist_ok=True)
    SSH_KNOWN_HOSTS_PATH.chmod(0o600)
except Exception:
    pass

logger = logging.getLogger("cluster_tui")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_FILE_PATH, mode="a")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


def load_config() -> Dict[str, Any]:
    if CONFIG_FILE_PATH.exists():
        try:
            return json.loads(CONFIG_FILE_PATH.read_text())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load config %s: %s", CONFIG_FILE_PATH, exc)
    return {"default_time_server": "", "alert_thresholds": {}}


def save_config(config: Dict[str, Any]) -> None:
    try:
        CONFIG_FILE_PATH.write_text(json.dumps(config, indent=2))
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to save config %s: %s", CONFIG_FILE_PATH, exc)


def password_auth_supported() -> bool:
    return shutil.which("sshpass") is not None


def set_ssh_password(password: Optional[str]) -> bool:
    """Store SSH password (empty string clears). Return True if accepted."""
    global SSH_PASSWORD
    if password:
        if not password_auth_supported():
            logger.warning("Password auth requested but sshpass is not installed; ignoring password.")
            SSH_PASSWORD = ""
            return False
        SSH_PASSWORD = password
        return True
    SSH_PASSWORD = ""
    return True


def log_check_status(host: str, check_name: str, status: str, summary: str) -> None:
    """Write a structured log entry for notable check outcomes."""
    if status != "FAIL":
        return
    logger.info("Check %s for %s -> %s | %s", check_name, host, status, summary)


if SSH_PASSWORD and not password_auth_supported():
    logger.warning("SSH_PASSWORD is set but sshpass is missing; falling back to key-based auth.")
    SSH_PASSWORD = ""


CHECK_NAMES = ["SSH", "Time", "iSCSI", "GFS2", "Corosync", "Pacemaker"]
HOST_REPAIR_STEPS: List[Tuple[str, str]] = [
    ("Restart iSCSI daemon", "systemctl restart iscsid"),
    ("Restart iscsi service", "systemctl restart iscsi"),
    ("Login to all iSCSI targets", "iscsiadm -m node --loginall=all"),
    ("Restart multipathd", "systemctl restart multipathd"),
    ("Flush stale multipath maps", "multipath -F"),
    ("Refresh multipath map", "multipath -r"),
    (
        "Rescan SCSI hosts",
        "bash -lc 'for host in /sys/class/scsi_host/host*; do echo \"- - -\" > \"$host/scan\"; done'",
    ),
    ("Remount GFS2 volumes", "mount -a -t gfs2"),
    ("Restart Corosync", "systemctl restart corosync"),
    ("Restart Pacemaker", "systemctl restart pacemaker"),
    ("Start cluster services locally", "pcs cluster start"),
]

CONTROLLER_NODE_REPAIR_STEPS: List[Tuple[str, str]] = [
    ("Confirm fencing cleared for {host}", "pcs stonith confirm {host}"),
    ("Cleanup fencing history for {host}", "stonith_admin --cleanup {host}"),
    ("Bring node out of standby", "pcs node unstandby {host}"),
    ("Start cluster services on {host}", "pcs cluster start {host}"),
    ("Cleanup resources (all services)", "pcs resource cleanup"),
]

CONTROLLER_REPAIR_STEPS: List[Tuple[str, str]] = [
    ("Cleanup fencing history", "pcs stonith cleanup --all"),
    ("Start cluster everywhere", "pcs cluster start --all"),
    ("Cleanup failed resources", "pcs resource cleanup"),
]

Action = Tuple[str, bool, Optional[Callable[[], None]], Optional[str]]
SSH_COMMON_FLAGS = [
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    f"UserKnownHostsFile={SSH_KNOWN_HOSTS_PATH}",
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
]
SSH_BATCH_ONLY_FLAGS = ["-o", "BatchMode=yes"]


def quote_for_shell(command: str) -> str:
    """Return COMMAND quoted for safe copy/paste usage."""
    if not command:
        return "''"
    if "'" not in command:
        return f"'{command}'"
    if '"' not in command:
        return f'"{command}"'
    return shlex.quote(command)


def tutorial_ssh_line(target: str, command: str) -> str:
    """Format the SSH invocation shown in the tutorial panel."""
    return f"ssh {target} {quote_for_shell(command)}"


TUTORIAL_CONTENT: Dict[str, Dict[str, str]] = {
    "check_host": {
        "title": "Check selected host",
        "reason": "Run SSH, storage, and cluster verifications before touching {host}.",
        "notes": "Outputs are saved to {log_file} for later review.",
    },
    "check_all": {
        "title": "Run Check All",
        "reason": "Baseline every configured host to understand overall blast radius.",
        "notes": "Useful before/after big maintenance windows.",
    },
    "repair_host": {
        "title": "Repair selected host",
        "reason": "Rebuild storage paths on {host}, clear fencing, and restart cluster services.",
        "notes": "Finishes by re-running the health checks above.",
    },
    "repair_all": {
        "title": "Repair all hosts",
        "reason": "Queue repairs in priority order, then restart cluster-wide services and GFS resources.",
        "notes": "Use after confirming at least {min_nodes} healthy GFS nodes.",
    },
}

def build_ssh_target(host: str) -> str:
    """
    Convert a raw host identifier into a user@host target.
    If the input already contains '@', return it unchanged.
    Otherwise prepend SSH_USER.
    """
    host = host.strip()
    if "@" in host:
        return host
    return f"{SSH_USER}@{host}"


def parse_cli_hosts(argv: List[str]) -> List[Tuple[str, str]]:
    hosts: List[Tuple[str, str]] = []
    for arg in argv:
        arg = arg.strip()
        if not arg:
            continue
        if "," in arg:
            name, addr = arg.split(",", 1)
            hosts.append((name.strip(), addr.strip()))
        else:
            if "@" in arg:
                name = arg
                addr = arg
            else:
                name = arg
                addr = arg
            hosts.append((name, addr))
    return hosts


def get_host_target(name: str) -> str:
    return HOST_TARGETS.get(name, name)


def host_index(name: str) -> int:
    for idx, (candidate, _) in enumerate(CLUSTER_HOSTS):
        if candidate == name:
            return idx
    return -1


def get_primary_controller(default_name: str, default_target: str) -> Tuple[str, str]:
    if CLUSTER_HOSTS:
        return CLUSTER_HOSTS[0]
    return default_name, default_target


@dataclass
class CheckResult:
    name: str
    status: str = "UNCHECKED"
    summary: str = "Not run yet"
    output: str = ""


@dataclass
class HostStatus:
    host: str
    checks: List[CheckResult] = field(default_factory=list)
    last_run_time: Optional[datetime] = None
    repair_entries: List[str] = field(default_factory=list)

    def get_check(self, check_name: str) -> CheckResult:
        for check in self.checks:
            if check.name == check_name:
                return check
        raise KeyError(f"Unknown check {check_name}")

    def set_check(
        self,
        check_name: str,
        status: str,
        summary: str,
        output: str,
    ) -> None:
        check = self.get_check(check_name)
        check.status = status
        check.summary = summary
        check.output = output.strip()
        log_check_status(self.host, check_name, status, summary)

    def add_repair_entry(self, summary: str, output: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"== Repair: {summary} ({timestamp}) =="
        payload = output.strip() or "No repair output captured."
        self.repair_entries.append(f"{header}\n{payload}")

    def overall_status(self) -> str:
        statuses = [c.status for c in self.checks]
        if all(status == "UNCHECKED" for status in statuses):
            return "UNCHECKED"
        if any(status == "FAIL" for status in statuses):
            return "FAIL"
        if all(status == "OK" for status in statuses):
            return "OK"
        return "WARN"

    def combined_output(self) -> str:
        blocks = []
        for check in self.checks:
            if check.output:
                blocks.append(f"== {check.name} ==\n{check.output}")
        blocks.extend(self.repair_entries)
        return "\n\n".join(blocks) if blocks else "No log output for this host yet."


def create_default_checks() -> List[CheckResult]:
    return [CheckResult(name=name) for name in CHECK_NAMES]


def format_remote_output(host: str, command: str, exit_code: int, stdout: str, stderr: str) -> str:
    parts = [
        f"$ ssh {build_ssh_target(host)} \"{command}\"",
        f"exit code: {exit_code}",
    ]
    if stdout:
        parts.append("STDOUT:\n" + stdout.strip())
    if stderr:
        parts.append("STDERR:\n" + stderr.strip())
    return "\n".join(parts).strip()


def log_remote_result(host: str, command: str, exit_code: int, stdout: str, stderr: str) -> None:
    formatted = format_remote_output(host, command, exit_code, stdout, stderr)
    logger.info("Remote command result:\n%s", formatted)


def run_remote_command(host: str, command: str, timeout: int = 10) -> Tuple[int, str, str]:
    """Execute COMMAND on HOST through the local ssh client."""
    ssh_target = build_ssh_target(host)
    if SSH_PASSWORD:
        if shutil.which("sshpass") is None:
            stderr = "sshpass is required for password auth but was not found (install it, e.g. sudo apt install sshpass)."
            logger.error(stderr)
            return 1, "", stderr
        base_cmd = ["sshpass", "-p", SSH_PASSWORD, "ssh"]
        ssh_flags = list(SSH_COMMON_FLAGS)
    else:
        base_cmd = ["ssh"]
        ssh_flags = list(SSH_COMMON_FLAGS) + SSH_BATCH_ONLY_FLAGS
    full_command = base_cmd + ssh_flags + [ssh_target, command]
    try:
        completed = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        log_remote_result(host, command, completed.returncode, completed.stdout, completed.stderr)
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\nCommand timed out after {timeout} seconds."
        log_remote_result(host, command, 124, stdout, stderr)
        return 124, stdout, stderr
    except FileNotFoundError as exc:
        stderr = f"{exc.filename} was not found."
        if SSH_PASSWORD and exc.filename == "sshpass":
            stderr = "sshpass is required when SSH_PASSWORD is set but was not found."
        log_remote_result(host, command, 1, "", stderr)
        return 1, "", stderr
    except Exception as exc:  # pragma: no cover - defensive
        stderr = f"{type(exc).__name__}: {exc}"
        log_remote_result(host, command, 255, "", stderr)
        return 255, "", stderr


def joined_outputs(outputs: Iterable[str]) -> str:
    return "\n\n".join(part for part in outputs if part).strip()


def run_step_sequence(remote_target: str, steps: List[Tuple[str, str]], *, timeout: int) -> Tuple[bool, str]:
    """Run STEPS on REMOTE_TARGET, returning success flag and combined log output."""
    outputs: List[str] = []
    success = True
    for description, command in steps:
        exit_code, stdout, stderr = run_remote_command(remote_target, command, timeout=timeout)
        outputs.append(
            f"{description}:\n" + format_remote_output(remote_target, command, exit_code, stdout, stderr)
        )
        if exit_code != 0:
            success = False
    return success, "\n\n".join(outputs).strip()


def check_ssh(host: str, target: str) -> CheckResult:
    exit_code, stdout, stderr = run_remote_command(target, "echo ok")
    output = format_remote_output(target, "echo ok", exit_code, stdout, stderr)
    summary = "SSH connectivity verified" if exit_code == 0 else "SSH command failed"
    status = "OK" if exit_code == 0 else "FAIL"
    return CheckResult(name="SSH", status=status, summary=summary, output=output)


def _parse_bool_flag(lines: List[str], key: str) -> Optional[bool]:
    for line in lines:
        if not line.startswith(key):
            continue
        _, _, val = line.partition("=")
        val = val.strip().lower()
        if val in ("yes", "1", "true"):
            return True
        if val in ("no", "0", "false"):
            return False
    return None


def check_time(host: str, target: str) -> CheckResult:
    """Detect NTP sync and drift between local and remote clocks."""
    command = (
        "sh -c 'date +%s; "
        "chronyc tracking || true; "
        "timedatectl show -p NTPSynchronized -p SystemClockSynchronized -p TimeUSec -p Timezone'"
    )
    exit_code, stdout, stderr = run_remote_command(target, command)
    output = format_remote_output(target, command, exit_code, stdout, stderr)
    if exit_code != 0 or not stdout.strip():
        return CheckResult(
            name="Time",
            status="FAIL",
            summary="Unable to read remote clock",
            output=output,
        )

    lines = stdout.splitlines()
    status = "OK"
    summary_parts: List[str] = []
    drift_seconds: Optional[int] = None
    try:
        remote_epoch = int(lines[0].strip())
        local_epoch = int(time.time())
        drift_seconds = abs(local_epoch - remote_epoch)
        summary_parts.append(f"drift_seconds={drift_seconds}")
        summary_parts.append(f"drift_threshold={TIME_DRIFT_THRESHOLD_SECS}")
        if drift_seconds >= TIME_DRIFT_THRESHOLD_SECS:
            summary_parts.append("clock drift exceeds threshold")
            status = "FAIL"
    except Exception:
        summary_parts.append("drift=unknown")
        status = "WARN"

    ntp_synced = _parse_bool_flag(lines[1:], "NTPSynchronized")
    clock_synced = _parse_bool_flag(lines[1:], "SystemClockSynchronized")
    if ntp_synced is False or clock_synced is False:
        status = "FAIL"
        summary_parts.append("ntp_sync=false")
    elif ntp_synced is True or clock_synced is True:
        summary_parts.append("ntp_sync=true")
    else:
        summary_parts.append("ntp_sync=unknown")
        status = "WARN"

    summary = "; ".join(summary_parts)
    return CheckResult(name="Time", status=status, summary=summary, output=output)


def check_iscsi(host: str, target: str) -> CheckResult:
    commands = [
        "iscsiadm -m session",
        "multipath -ll",
    ]
    outputs = []
    failed_detail = ""
    success = True
    for command in commands:
        exit_code, stdout, stderr = run_remote_command(target, command)
        outputs.append(format_remote_output(target, command, exit_code, stdout, stderr))
        if exit_code != 0:
            success = False
            failed_detail = f"{command} (rc={exit_code})"
    status = "OK" if success else "FAIL"
    summary = "Sessions and multipath look fine" if success else f"{failed_detail} failed"
    return CheckResult(
        name="iSCSI",
        status=status,
        summary=summary,
        output=joined_outputs(outputs),
    )


def check_gfs2(host: str, target: str) -> CheckResult:
    command = "mount | grep gfs2"
    exit_code, stdout, stderr = run_remote_command(target, command)
    output = format_remote_output(target, command, exit_code, stdout, stderr)
    status = "OK" if exit_code == 0 else "FAIL"
    summary = "GFS2 mounts detected" if status == "OK" else "No active GFS2 mount found"
    return CheckResult(name="GFS2", status=status, summary=summary, output=output)


def check_corosync(host: str, target: str) -> CheckResult:
    command = "systemctl is-active corosync"
    exit_code, stdout, stderr = run_remote_command(target, command)
    output = format_remote_output(target, command, exit_code, stdout, stderr)
    active = stdout.strip() == "active" and exit_code == 0
    status = "OK" if active else "FAIL"
    summary = "Corosync is active" if active else "Corosync is not active"
    return CheckResult(name="Corosync", status=status, summary=summary, output=output)


def check_pacemaker(host: str, host_target: str) -> CheckResult:
    if CLUSTER_HOSTS:
        controlling_name, controlling_target = CLUSTER_HOSTS[0]
    else:
        controlling_name, controlling_target = host, host_target
    command = "pcs status"
    exit_code, stdout, stderr = run_remote_command(controlling_target, command)
    output = format_remote_output(controlling_target, command, exit_code, stdout, stderr)
    status = "OK" if exit_code == 0 else "FAIL"
    summary = (
        f"pcs status reported OK via {controlling_name}"
        if status == "OK"
        else f"pcs status failed via {controlling_name}"
    )
    return CheckResult(name="Pacemaker", status=status, summary=summary, output=output)


def _extract_drift(summary: str) -> Optional[int]:
    for part in summary.split(";"):
        part = part.strip()
        if part.startswith("drift_seconds="):
            _, _, val = part.partition("=")
            try:
                return int(val.strip())
            except ValueError:
                return None
    return None


def correct_clock_drift(host: str, target: str, drift_seconds: Optional[int]) -> Tuple[bool, str]:
    drift_text = f"{drift_seconds}s" if drift_seconds is not None else "unknown"
    logger.info("Clock drift detected on %s (%s), attempting correction (drift=%s)", host, target, drift_text)
    steps: List[Tuple[str, str]] = [
        ("Ensure NTP is enabled", "timedatectl set-ntp true"),
        ("Force chrony step", "chronyc -a makestep || chronyc makestep || true"),
        ("Restart chrony/chronyd", "systemctl restart chronyd || systemctl restart chrony || true"),
    ]
    return run_step_sequence(target, steps, timeout=45)


def enforce_time_guard(host: str, target: str) -> Tuple[bool, str]:
    """Run a fast time check/repair guard. Returns (ok_to_continue, details_if_blocked)."""
    time_result = check_time(host, target)
    drift_seconds = _extract_drift(time_result.summary)
    if time_result.status == "OK":
        return True, ""
    if drift_seconds is not None and drift_seconds < TIME_DRIFT_THRESHOLD_SECS:
        return True, ""
    fix_success, fix_details = correct_clock_drift(host, target, drift_seconds)
    summary = f"Clock drift guard triggered on {host}: drift={drift_seconds}s; correction {'succeeded' if fix_success else 'failed'}"
    combined = "\n\n".join(part for part in (time_result.output, fix_details) if part).strip()
    return False, f"{summary}\n\n{combined}"


def perform_host_checks(host: str, target: Optional[str] = None) -> HostStatus:
    """Run the health check chain for HOST and return a populated HostStatus."""
    resolved_target = target or get_host_target(host)
    logger.info("Starting health checks for %s (%s)", host, resolved_target)
    status = HostStatus(host=host, checks=create_default_checks(), last_run_time=datetime.now())

    ssh_result = check_ssh(host, resolved_target)
    status.set_check("SSH", ssh_result.status, ssh_result.summary, ssh_result.output)
    if ssh_result.status != "OK":
        for later in ("Time", "iSCSI", "GFS2", "Corosync", "Pacemaker"):
            status.set_check(
                later,
                "SKIPPED",
                "Skipped because SSH failed",
                "",
            )
        return status

    time_result = check_time(host, resolved_target)
    status.set_check("Time", time_result.status, time_result.summary, time_result.output)

    iscsi_result = check_iscsi(host, resolved_target)
    status.set_check("iSCSI", iscsi_result.status, iscsi_result.summary, iscsi_result.output)

    if iscsi_result.status == "FAIL":
        status.set_check("GFS2", "SKIPPED", "Skipped because storage is unhealthy", "")
    else:
        gfs2_result = check_gfs2(host, resolved_target)
        status.set_check("GFS2", gfs2_result.status, gfs2_result.summary, gfs2_result.output)

    corosync_result = check_corosync(host, resolved_target)
    status.set_check(
        "Corosync",
        corosync_result.status,
        corosync_result.summary,
        corosync_result.output,
    )

    pacemaker_result = check_pacemaker(host, resolved_target)
    status.set_check(
        "Pacemaker",
        pacemaker_result.status,
        pacemaker_result.summary,
        pacemaker_result.output,
    )

    logger.info("Completed health checks for %s with overall %s", host, status.overall_status())
    return status


def repair_host_and_check(host: str) -> HostStatus:
    target = get_host_target(host)
    logger.info("Starting repair workflow for %s (%s)", host, target)
    time_ok, time_details = enforce_time_guard(host, target)
    if not time_ok:
        status = perform_host_checks(host, target)
        status.add_repair_entry("Clock drift corrected; rerun repairs", time_details)
        logger.info("Aborting repair workflow for %s due to clock drift guard", host)
        return status

    host_success, host_details = run_step_sequence(target, HOST_REPAIR_STEPS, timeout=60)
    host_summary = "Host level repair completed" if host_success else "Host level repair finished with errors"

    controller_success, controller_details = run_controller_node_repairs(host)
    controller_summary = (
        f"Controller repair for {host} completed"
        if controller_success
        else f"Controller repair for {host} reported errors"
    )

    service_success, service_details = verify_cluster_services(host)
    service_summary = (
        "Pacemaker/Corosync verification passed"
        if service_success
        else "Pacemaker/Corosync verification failed"
    )

    combined_details = "\n\n".join(part for part in (host_details, controller_details, service_details) if part).strip()
    combined_summary = f"{host_summary}; {controller_summary}; {service_summary}"

    status = perform_host_checks(host, target)
    status.add_repair_entry(combined_summary, combined_details)
    logger.info("Repair workflow for %s finished with %s", host, status.overall_status())
    return status


def run_controller_node_repairs(host: str) -> Tuple[bool, str]:
    fallback_target = get_host_target(host)
    _, controller_target = get_primary_controller(host, fallback_target)
    steps = [
        (description.format(host=host), command.format(host=host))
        for description, command in CONTROLLER_NODE_REPAIR_STEPS
    ]
    return run_step_sequence(controller_target, steps, timeout=90)


def detect_clone_resources(controller_target: str, prefixes: Tuple[str, ...]) -> List[str]:
    exit_code, stdout, stderr = run_remote_command(controller_target, "pcs status", timeout=60)
    if exit_code != 0:
        return []

    clones: List[str] = []
    seen = set()
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if "Clone Set:" not in line:
            continue
        _, _, remainder = line.partition("Clone Set:")
        remainder = remainder.strip()
        if not remainder:
            continue
        clone_name = remainder.split()[0].strip("[]:,").rstrip(":")
        lowered = clone_name.lower()
        if any(lowered.startswith(prefix.lower()) for prefix in prefixes):
            if clone_name and clone_name not in seen:
                clones.append(clone_name)
                seen.add(clone_name)
    return clones


def detect_stonith_resources(controller_target: str) -> List[str]:
    exit_code, stdout, stderr = run_remote_command(controller_target, "pcs status", timeout=60)
    if exit_code != 0:
        return []

    resources: List[str] = []
    seen = set()
    for raw_line in stdout.splitlines():
        if "(stonith:" not in raw_line:
            continue
        name = raw_line.strip().split()[0].strip()
        if name and name not in seen:
            resources.append(name)
            seen.add(name)
    return resources


def _parse_offline_nodes(pcs_output: str) -> List[str]:
    offline: List[str] = []
    for raw_line in pcs_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        upper_line = line.upper()
        if "OFFLINE:" in upper_line:
            _, _, remainder = upper_line.partition("OFFLINE:")
            for token in remainder.replace(",", " ").split():
                name = token.strip().lower()
                if name and name not in offline:
                    offline.append(name)
        elif "UNREACHABLE" in upper_line or "UNCLEAN" in upper_line:
            tokens = line.split()
            if tokens:
                name = tokens[0].strip().strip(":").lower()
                if name and name not in offline:
                    offline.append(name)
        elif upper_line.startswith("NODE") and "OFFLINE" in upper_line:
            tokens = line.split()
            if tokens:
                # "Node e1 (OFFLINE)" -> pick second token
                if len(tokens) > 1:
                    name = tokens[1].strip().strip(":").lower()
                    if name and name not in offline:
                        offline.append(name)
    return offline


def count_offline_nodes(controller_target: str) -> Tuple[int, List[str], str]:
    command = "pcs status --full"
    exit_code, stdout, stderr = run_remote_command(controller_target, command, timeout=90)
    formatted_output = format_remote_output(controller_target, command, exit_code, stdout, stderr)
    offline_nodes = _parse_offline_nodes(stdout) if exit_code == 0 else []
    count_down = len(offline_nodes)
    if exit_code != 0 and not offline_nodes:
        count_down = len(CLUSTER_HOSTS) or len(CLUSTER_NODE_LIST)
    logger.info(
        "pcs status --full parsed offline nodes: count_down=%s nodes=%s rc=%s",
        count_down,
        offline_nodes or "none",
        exit_code,
    )
    return count_down, offline_nodes, formatted_output


def check_cluster_storage_health(controller_target: str) -> Tuple[bool, str, List[str]]:
    outputs: List[str] = []
    storage_ok = True
    commands: List[Tuple[str, str]] = [
        ("Check iSCSI sessions", "iscsiadm -m session"),
        ("Check multipath devices", "multipath -ll"),
        ("PCS resource status", "pcs resource status"),
    ]
    for description, command in commands:
        code, out, err = run_remote_command(controller_target, command, timeout=60)
        outputs.append(f"{description}:\n" + format_remote_output(controller_target, command, code, out, err))
        if code != 0:
            storage_ok = False
    dlm_clones = detect_clone_resources(controller_target, ("dlm",))
    gfs_clones = detect_clone_resources(controller_target, ("gfs",))
    resources = RECOVERY_RESOURCE_LIST or dlm_clones + gfs_clones
    if not resources:
        storage_ok = False
        outputs.append("No DLM/GFS clone resources detected via pcs status")
    details = "\n\n".join(part for part in outputs if part).strip()
    return storage_ok, details, resources


def repair_gfs2_resources(controller_target: str) -> Tuple[bool, str]:
    stonith_resources = detect_stonith_resources(controller_target)
    dlm_clones = detect_clone_resources(controller_target, ("dlm",))
    gfs_clones = detect_clone_resources(controller_target, ("gfs",))

    steps: List[Tuple[str, str]] = []
    for res in stonith_resources:
        steps.append((f"Enable fencing device {res}", f"pcs resource enable {res}"))
        steps.append((f"Cleanup fencing device {res}", f"pcs resource cleanup {res}"))
    for clone in dlm_clones:
        steps.append((f"Enable DLM clone {clone}", f"pcs resource enable {clone}"))
        steps.append((f"Cleanup DLM clone {clone}", f"pcs resource cleanup {clone}"))
    for clone in gfs_clones:
        steps.append((f"Enable GFS2 clone {clone}", f"pcs resource enable {clone}"))
        steps.append((f"Cleanup GFS2 clone {clone}", f"pcs resource cleanup {clone}"))

    if not steps:
        return True, "No fencing/DLM/GFS2 resources detected via pcs status"

    success, step_details = run_step_sequence(controller_target, steps, timeout=90)
    detected_parts = []
    if stonith_resources:
        detected_parts.append(f"Fencing: {', '.join(stonith_resources)}")
    if dlm_clones:
        detected_parts.append(f"DLM: {', '.join(dlm_clones)}")
    if gfs_clones:
        detected_parts.append(f"GFS2: {', '.join(gfs_clones)}")
    header = "Detected resources: " + "; ".join(detected_parts)
    combined_details = "\n\n".join(part for part in (header, step_details) if part).strip()
    return success, combined_details


def run_cluster_level_repairs(controller_target: str) -> Tuple[str, str]:
    start_ts = datetime.now()
    logger.info(
        "Cluster recovery start: controller_target=%s host=%s at %s",
        controller_target,
        socket.gethostname(),
        start_ts.isoformat(),
    )
    count_down, offline_nodes, pcs_full_details = count_offline_nodes(controller_target)
    storage_ok, storage_details, resources = check_cluster_storage_health(controller_target)

    resource_steps: List[Tuple[str, str]] = []
    for res in resources:
        resource_steps.extend(
            [
                (f"Restart resource {res}", f"pcs resource restart {res}"),
                (f"Enable resource {res}", f"pcs resource enable {res}"),
                (f"Check resource {res}", f"pcs resource status {res}"),
            ]
        )

    full_recovery_steps: List[Tuple[str, str]] = [
        ("Sync Corosync config", "pcs cluster sync corosync"),
        ("Reload Corosync", "pcs cluster reload corosync"),
        ("PCS status (full)", "pcs status --full"),
        ("pcsd service status", "systemctl status pcsd.service"),
        ("Cleanup all resources", "pcs resource cleanup"),
        ("List current resources", "pcs resource list"),
    ] + resource_steps + CONTROLLER_REPAIR_STEPS

    partial_recovery_steps: List[Tuple[str, str]] = [
        ("Cleanup resources", "pcs resource cleanup"),
        ("PCS status (full)", "pcs status --full"),
    ] + resource_steps + CONTROLLER_REPAIR_STEPS

    storage_recovery_steps: List[Tuple[str, str]] = [
        ("Re-run iSCSI session display", "iscsiadm -m session || true"),
        ("Re-run PCS resource status", "pcs resource status"),
    ] + resource_steps

    chosen_steps: List[Tuple[str, str]] = []
    path_taken = "noop"
    if count_down >= 2:
        path_taken = "full"
        chosen_steps = full_recovery_steps
    elif count_down == 1:
        path_taken = "partial"
        chosen_steps = partial_recovery_steps
    elif not storage_ok:
        path_taken = "storage"
        chosen_steps = storage_recovery_steps

    step_success = True
    step_details = "No recovery actions necessary; storage and quorum look healthy."
    if chosen_steps:
        step_success, step_details = run_step_sequence(controller_target, chosen_steps, timeout=90)

    gfs_success = True
    gfs_details = ""
    if path_taken != "noop":
        gfs_success, gfs_details = repair_gfs2_resources(controller_target)

    summary_parts = [
        f"count_down={count_down} offline={offline_nodes or 'none'} path={path_taken}",
        "Cluster level recovery completed" if step_success else "Cluster level recovery reported errors",
        "Storage/DLM/GFS repair completed" if gfs_success else "Storage/DLM/GFS repair reported errors",
    ]
    details = "\n\n".join(
        part for part in (pcs_full_details, storage_details, step_details, gfs_details) if part
    ).strip()
    elapsed = (datetime.now() - start_ts).total_seconds()
    logger.info(
        "Cluster recovery end: path=%s success=%s gfs_success=%s elapsed=%.1fs",
        path_taken,
        step_success,
        gfs_success,
        elapsed,
    )
    return "; ".join(summary_parts), details


def verify_cluster_services(host: str) -> Tuple[bool, str]:
    target = get_host_target(host)
    corosync_result = check_corosync(host, target)
    pacemaker_result = check_pacemaker(host, target)
    lines = [
        f"Corosync verification: {corosync_result.summary} (status={corosync_result.status})",
        corosync_result.output,
        f"Pacemaker verification: {pacemaker_result.summary} (status={pacemaker_result.status})",
        pacemaker_result.output,
    ]
    success = corosync_result.status == "OK" and pacemaker_result.status == "OK"
    logger.info("Service verification for %s: %s", host, "OK" if success else "FAILED")
    details = "\n\n".join(part for part in lines if part).strip()
    return success, details


class VMEClusterUI:
    SPINNER_FRAMES = "|/-\\"

    def __init__(self, stdscr: Any, config: Optional[Dict[str, Any]] = None) -> None:
        self.stdscr = stdscr
        self.host_statuses: Dict[str, HostStatus] = {
            name: HostStatus(host=name, checks=create_default_checks())
            for name, _ in CLUSTER_HOSTS
        }
        self.queue: queue.Queue[Tuple[str, object]] = queue.Queue()
        self.messages: Deque[str] = deque(maxlen=5)
        self.selected_entry_index = 0
        self.selected_action_index = 0
        self.focus: str = "list"
        self.running = True
        self.check_all_completed = False
        self._job_seq = 0
        self._active_jobs: Dict[int, str] = {}
        self._spinner_index = 0
        self.view_stack: List[str] = ["main"]
        self.config: Dict[str, Any] = config or {
            "default_time_server": "",
            "alert_thresholds": {},
        }
        self._init_curses()

    # ------------------------------------------------------------------ UI ---
    def _init_curses(self) -> None:
        curses.curs_set(0)
        self.stdscr.timeout(200)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(MENU_COLOR_PAIR, curses.COLOR_MAGENTA, -1)
            curses.init_pair(TITLE_COLOR_PAIR, curses.COLOR_WHITE, curses.COLOR_BLUE)

    # ------------------------------------------------------- view helpers ---
    @property
    def current_view(self) -> str:
        return self.view_stack[-1] if self.view_stack else "main"

    def push_view(self, view: str) -> None:
        if not view:
            return
        self.view_stack.append(view)
        self.selected_entry_index = 0
        self.selected_action_index = 0

    def pop_view(self) -> None:
        if len(self.view_stack) > 1:
            self.view_stack.pop()
        self.selected_entry_index = 0
        self.selected_action_index = 0

    def _menu_for_view(self, view: str) -> List[Tuple[str, str, str]]:
        if view == "main":
            return MAIN_MENU
        if view == "cluster_health":
            return CLUSTER_HEALTH_MENU
        if view == "vm_inventory":
            return VM_INVENTORY_MENU
        if view == "datastore":
            return DATASTORE_MENU
        if view == "hosts_config":
            return HOST_CONFIG_MENU
        if view == "logs_events":
            return LOGS_EVENTS_MENU
        if view == "config_settings":
            return CONFIG_SETTINGS_MENU
        return []

    def _menu_label_desc(self, view: str, key: str) -> Tuple[str, str]:
        for item_key, label, desc in self._menu_for_view(view):
            if item_key == key:
                return label, desc
        return key, ""

    def run(self) -> None:
        while self.running:
            self.process_queue()
            self.draw()
            key = self.stdscr.getch()
            if key == -1:
                continue
            self.handle_key(key)

    def draw(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 10 or width < 40:
            self.stdscr.addstr(0, 0, "Terminal window is too small.")
            self.stdscr.refresh()
            return
        title_height = self.draw_title_bar(width)
        remaining_height = max(0, height - title_height)
        if remaining_height <= 0:
            self.stdscr.refresh()
            return
        host_panel_width = min(max(24, width // 3), width - 24)
        start_y = title_height
        self.draw_host_panel(start_y, 0, remaining_height, host_panel_width)
        self.draw_vertical_line(start_y, host_panel_width, remaining_height)
        detail_start_x = host_panel_width + 1
        detail_width = max(1, width - detail_start_x)
        self.draw_detail_panel(start_y, detail_start_x, detail_width, remaining_height)
        self.stdscr.refresh()

    def draw_title_bar(self, width: int) -> int:
        view = self.current_view.replace("_", " ").title()
        title = f"VME Cluster TUI {APP_VERSION} [{view}] | Log: {LOG_FILE_DISPLAY}"
        attr = curses.A_BOLD
        if curses.has_colors():
            attr |= curses.color_pair(TITLE_COLOR_PAIR)
        padded = title[:width].ljust(width)
        self.safe_addstr(0, 0, padded, attr)
        spacer = " " * max(0, width)
        self.safe_addstr(1, 0, spacer[:width])
        return 2

    def draw_host_panel(self, start_y: int, start_x: int, height: int, width: int) -> None:
        if height <= 2 or width <= 4:
            return
        title = self._panel_title()
        self.safe_addstr(start_y, start_x + 1, title, curses.A_BOLD)
        entries = self.get_entries()
        total_entries = len(entries)
        list_height = max(1, height - 6)
        if total_entries == 0:
            return
        visible_entries = min(total_entries, list_height)
        max_start = max(0, total_entries - visible_entries)
        start_index = min(max(0, self.selected_entry_index - visible_entries + 1), max_start)
        for offset in range(visible_entries):
            entry_index = start_index + offset
            if entry_index >= total_entries:
                break
            row_y = start_y + 2 + offset
            entry_kind, entry_value = entries[entry_index]
            entry_text, attr = self._entry_label_and_attr(entry_kind, entry_value)
            if entry_index == self.selected_entry_index:
                attr |= curses.A_REVERSE
                if self.focus != "list":
                    attr |= curses.A_DIM
            self.safe_addstr(row_y, start_x + 1, entry_text[: width - 2], attr)
        footer_start = start_y + 2 + visible_entries
        if footer_start >= start_y + height:
            return
        self.safe_hline(footer_start, start_x, width)
        info_line = "Keys: ←/→ move focus • Enter selects • p password • q quits"
        self.safe_addstr(min(footer_start + 1, start_y + height - 1), start_x + 1, info_line[: width - 2])
        busy_line = self.busy_status_text()
        if footer_start + 2 < start_y + height:
            self.safe_addstr(footer_start + 2, start_x + 1, busy_line[: width - 2], curses.A_DIM)

    def draw_vertical_line(self, start_y: int, x: int, height: int) -> None:
        for offset in range(height):
            self.safe_addch(start_y + offset, x, curses.ACS_VLINE)

    def _panel_title(self) -> str:
        view = self.current_view
        if view == "main":
            return "Main Menu"
        if view == "cluster_health":
            return "Cluster Health and Repair"
        if view == "node_status":
            return "Node Status and Quorum"
        if view == "gfs_repair":
            return "GFS / iSCSI Repair Wizard"
        if view == "time_ntp":
            return "Time / NTP Checks"
        if view == "health_summary":
            return "Cluster Health Summary"
        if view == "vm_inventory":
            return "VM Inventory and Control"
        if view == "datastore":
            return "Datastore and Storage Overview"
        if view == "hosts_config":
            return "Hosts and Node Configuration"
        if view == "logs_events":
            return "Logs and Events"
        if view == "config_settings":
            return "Configuration and Settings"
        return "Menu"

    def _entry_label_and_attr(self, entry_kind: str, entry_value: Optional[str]) -> Tuple[str, int]:
        attr = curses.A_NORMAL
        view = self.current_view
        if entry_kind == "host" and entry_value:
            status = self.host_statuses[entry_value].overall_status()
            entry_text = f"{status:<9} {entry_value}"
            attr |= self.status_to_attr(status)
            return entry_text, attr
        if entry_kind == "check_all":
            entry_text = ">> Check all hosts"
            attr |= self.menu_option_attr()
            return entry_text, attr
        if entry_kind == "repair_all":
            count = len(self._hosts_needing_repair())
            entry_text = f">> Repair all hosts ({count} pending)" if count else ">> Repair all hosts"
            attr |= self.menu_option_attr()
            return entry_text, attr
        if entry_kind == "back":
            attr |= self.menu_option_attr()
            if view in ("node_status", "gfs_repair", "time_ntp", "health_summary"):
                return ">> Back to Cluster Health menu", attr
            return ">> Back", attr
        if entry_kind == "exit":
            return ">> Exit (q)", self.menu_option_attr()
        if entry_kind in {"menu", "submenu"} and entry_value:
            label, _ = self._menu_label_desc(view if entry_kind == "submenu" else "main", entry_value)
            return label, self.menu_option_attr()
        if entry_kind == "placeholder" and entry_value:
            return entry_value, self.menu_option_attr()
        if entry_kind == "summary":
            return "Cluster health summary", self.menu_option_attr()
        if entry_kind == "export_summary":
            return "Export health summary", self.menu_option_attr()
        return (entry_value or "--"), attr

    def _menu_detail_lines(self, view: str, key: str) -> List[str]:
        label, desc = self._menu_label_desc(view, key)
        lines: List[str] = [label]
        if desc:
            lines.append(desc)
        lines.append("")
        if key == "cluster_health":
            lines.append("Navigate into Cluster Health to run node checks, GFS/iSCSI repair, and time sync tasks.")
        elif key == "vm_inventory":
            lines.append("Inventory and control VMs across hosts; actual VM APIs are TODO placeholders.")
        elif key == "datastore":
            lines.append("Storage overview with placeholders for Verge/storage APIs and exports.")
        elif key == "hosts_config":
            lines.append("Host-level config, network, and service controls (stubs).")
        elif key == "logs_events":
            lines.append("View and export logs; backup/snapshot checks are placeholders.")
        elif key == "config_settings":
            lines.append("Defaults for time server, alert thresholds, and TUI preferences (stubs).")
        elif key == "node_status":
            lines.append("Reuse the existing host health checks and quorum visibility.")
        elif key == "gfs_repair":
            lines.append("Runs the existing GFS/iSCSI repair wizard and controller cleanup logic.")
        elif key == "time_ntp":
            lines.append("Check time across hosts and configure NTP server (TODO hooks for chrony/ntpd).")
        elif key == "health_summary":
            lines.append("Summarize cluster storage/time status and export to a text file.")
        elif key == "vm_list":
            lines.append("List VMs per host with status (TODO: integrate VM inventory tooling).")
        elif key == "vm_manager":
            lines.append("VM manager service control; service name/commands are TODO stubs.")
        elif key == "vm_actions":
            lines.append("Select a VM and power on/off/reboot (stubbed).")
        elif key == "vm_alerts":
            lines.append("Placeholder for CPU/RAM or long-term powered-off VM alerts.")
        elif key == "ds_list":
            lines.append("List datastores via Verge or storage API (TODO).")
        elif key == "ds_health":
            lines.append("Show free/used and mount/health checks; thresholds TODO.")
        elif key == "ds_cleanup":
            lines.append("Placeholder for cleanup suggestions (snapshots, near-full datastores).")
        elif key == "ds_export":
            lines.append("Export datastore summary to CSV/text.")
        elif key == "net_health":
            lines.append("Network health view for bonds/VLANs/bridges (TODO commands).")
        elif key == "os_patch":
            lines.append("Placeholder for OS/kernel/pending updates per node.")
        elif key == "config_drift":
            lines.append("Placeholder for baseline comparison to detect drift.")
        elif key == "service_control":
            lines.append("Generic service control hooks for chosen services across hosts.")
        elif key == "cluster_logs":
            lines.append("Recent cluster logs with simple filters (TODO pager implementation).")
        elif key == "backups":
            lines.append("Backup/snapshot status placeholder.")
        elif key == "export_logs":
            lines.append("Export selected logs to a file.")
        elif key == "default_time_server":
            lines.append("Store a default time server and reuse for time sync operations.")
        elif key == "alert_thresholds":
            lines.append("Disk/CPU/etc thresholds (persisted config TODO).")
        elif key == "tui_prefs":
            lines.append("Keep the existing color scheme; add prefs later.")
        elif key == "help_about":
            lines.append(f"VME Cluster TUI built on cluster_tui logic ({APP_VERSION}).")
        lines.append("")
        return lines

    def draw_detail_panel(self, start_y: int, start_x: int, width: int, height: int) -> None:
        if height <= 0 or width <= 2:
            return
        padding_x = start_x + 1
        usable_width = max(1, width - 2)
        actions = self.current_actions()

        # Draw actions header.
        self.safe_addstr(start_y, padding_x, "Actions", curses.A_BOLD)
        action_area = 2
        for idx, (label, enabled, _, _) in enumerate(actions):
            attr = self.menu_option_attr(enabled)
            if self.focus == "actions" and idx == self.selected_action_index:
                attr |= curses.A_REVERSE
            self.safe_addstr(start_y + 1 + idx, padding_x, label[:usable_width], attr)
            action_area += 1
        tutorial_lines = self._tutorial_lines(actions, usable_width)
        for text in tutorial_lines:
            if action_area >= height:
                break
            attr = self._tutorial_line_attr(text)
            self.safe_addstr(start_y + action_area, padding_x, text[:usable_width], attr)
            action_area += 1
        if action_area < height:
            log_label = f"Log file: {LOG_FILE_DISPLAY}"
            log_attr = self.menu_option_attr()
            self.safe_addstr(
                start_y + action_area,
                padding_x,
                log_label[:usable_width],
                log_attr | curses.A_DIM,
            )
            action_area += 1
        detail_start = start_y + action_area
        detail_height = height - action_area
        if detail_height <= 0:
            return
        self.safe_hline(detail_start - 1, start_x, width)

        entry_kind, entry_value = self.current_entry_info()
        if entry_kind == "host" and entry_value:
            self.draw_host_detail(detail_start, start_x, width, detail_height, entry_value)
        elif entry_kind == "check_all":
            self.draw_cluster_summary(detail_start, start_x, width, detail_height)
        elif entry_kind == "repair_all":
            self.draw_repair_overview(detail_start, start_x, width, detail_height)
        elif entry_kind == "summary":
            self._draw_lines(detail_start, start_x, width, detail_height, self._health_summary_text().splitlines())
        elif entry_kind == "export_summary":
            self._draw_lines(
                detail_start,
                start_x,
                width,
                detail_height,
                ["Export the current health summary to disk.", "Action writes a timestamped text file next to the script."],
            )
        elif entry_kind in {"menu", "submenu"}:
            lines = self._menu_detail_lines(self.current_view if entry_kind == "submenu" else "main", entry_value or "")
            self._draw_lines(detail_start, start_x, width, detail_height, lines)
        elif entry_kind == "placeholder":
            self._draw_lines(detail_start, start_x, width, detail_height, [entry_value or ""])
        else:
            self.safe_addstr(detail_start, padding_x, "No details available.")

    def _draw_lines(self, start_y: int, start_x: int, width: int, height: int, lines: List[str]) -> None:
        padding_x = start_x + 1
        usable_width = max(1, width - 2)
        if height <= 0:
            return
        for idx, text in enumerate(lines):
            if idx >= height:
                break
            self.safe_addstr(start_y + idx, padding_x, text[:usable_width])

    def draw_host_detail(self, start_y: int, start_x: int, width: int, height: int, host: str) -> None:
        status = self.host_statuses[host]
        padding_x = start_x + 1
        usable_width = max(1, width - 2)
        lines: List[str] = [f"Host: {host}"]
        if status.last_run_time:
            lines.append(f"Last run: {status.last_run_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            lines.append("Checks have not been run yet.")
        lines.append("")
        lines.append("Checks:")
        for check in status.checks:
            summary_width = max(1, usable_width - 22)
            wrapped_summary = textwrap.wrap(check.summary, summary_width) or [""]
            first = f"{check.name:<10} {check.status:<9} {wrapped_summary[0]}".rstrip()
            lines.append(first[:usable_width])
            for line in wrapped_summary[1:]:
                lines.append((" " * 22 + line)[:usable_width])
        summary_height = min(len(lines), max(6, height // 3))
        for offset in range(min(summary_height, height)):
            self.safe_addstr(start_y + offset, padding_x, lines[offset])
        content_start = start_y + summary_height
        remaining_height = height - summary_height
        if remaining_height <= 2:
            return
        self.safe_hline(content_start, start_x, width)
        content_start += 1
        remaining_height -= 1
        message_lines = list(self.messages)[-3:]
        message_block = len(message_lines) + 2 if message_lines else 0
        log_height = max(1, remaining_height - message_block)
        log_lines = status.combined_output().splitlines() or ["No log output yet."]
        log_to_show = log_lines[-log_height:]
        log_header = f"Logs (file: {LOG_FILE_PATH.name}):"
        self.safe_addstr(content_start, padding_x, log_header[:usable_width], self.menu_option_attr())
        for idx, text in enumerate(log_to_show, start=1):
            row = content_start + idx
            if row >= start_y + height - message_block:
                break
            self.safe_addstr(row, padding_x, text[:usable_width])
        if message_lines:
            message_header_y = start_y + height - message_block
            self.safe_hline(message_header_y - 1, start_x, width)
            self.safe_addstr(message_header_y, padding_x, "Recent messages:", curses.A_BOLD)
            for i, text in enumerate(message_lines, start=1):
                row = message_header_y + i
                if row >= start_y + height:
                    break
                self.safe_addstr(row, padding_x, text[:usable_width])

    def draw_cluster_summary(self, start_y: int, start_x: int, width: int, height: int) -> None:
        padding_x = start_x + 1
        usable_width = max(1, width - 2)
        lines: List[str] = []
        warnings: List[str] = []
        if not self.check_all_completed:
            lines.append("Cluster-wide checks have not been run yet.")
            lines.append("Select 'Check all hosts' to gather current health.")
        else:
            lines.append("Cluster summary:")
            for name, _ in CLUSTER_HOSTS:
                status = self.host_statuses[name].overall_status()
                lines.append(f" - {name}: {status}")
            warnings = self._storage_quorum_warnings()
        if self.check_all_completed:
            if not self._hosts_needing_repair():
                lines.append("")
                if warnings:
                    lines.append("All hosts report OK, but storage quorum warnings are present (see below).")
                else:
                    lines.append("All hosts appear healthy.")
            else:
                lines.append("")
                lines.append("Some hosts need repair. Use the Repair All entry or fix individually.")
        if warnings:
            lines.append("")
            lines.extend(warnings)
        pcs_lines = self._pcs_recovery_lines(usable_width)
        if pcs_lines:
            lines.append("")
            lines.extend(pcs_lines)
        lines.append("")
        lines.extend(["Recent messages:"] + (list(self.messages)[-3:] or ["(no recent messages)"]))
        for idx in range(min(len(lines), height)):
            self.safe_addstr(start_y + idx, padding_x, lines[idx][:usable_width])

    def draw_repair_overview(self, start_y: int, start_x: int, width: int, height: int) -> None:
        padding_x = start_x + 1
        usable_width = max(1, width - 2)
        lines: List[str] = []
        if not self.check_all_completed:
            lines.append("Run 'Check all hosts' first to determine repair order.")
        else:
            hosts = self._order_hosts_for_repair(self._hosts_needing_repair())
            if not hosts:
                lines.append("All hosts are healthy. No repairs required.")
            else:
                lines.append("Planned repair order:")
                for idx, host in enumerate(hosts, start=1):
                    host_status = self.host_statuses[host].overall_status()
                    lines.append(f" {idx}. {host} ({host_status})")
        lines.append("")
        lines.extend(["Recent messages:"] + (list(self.messages)[-3:] or ["(no recent messages)"]))
        for idx in range(min(len(lines), height)):
            self.safe_addstr(start_y + idx, padding_x, lines[idx][:usable_width])

    def safe_addstr(self, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        height, width = self.stdscr.getmaxyx()
        if 0 <= y < height and 0 <= x < width:
            remaining = width - x
            if remaining <= 0:
                return
            try:
                self.stdscr.addnstr(y, x, text, remaining, attr)
            except curses.error:
                pass

    def safe_addch(self, y: int, x: int, ch: int) -> None:
        height, width = self.stdscr.getmaxyx()
        if 0 <= y < height and 0 <= x < width:
            try:
                self.stdscr.addch(y, x, ch)
            except curses.error:
                pass

    def safe_hline(self, y: int, x: int, width: int) -> None:
        height, screen_width = self.stdscr.getmaxyx()
        if y >= height:
            return
        draw_width = min(width, screen_width - x)
        if draw_width > 0:
            try:
                self.stdscr.hline(y, x, curses.ACS_HLINE, draw_width)
            except curses.error:
                pass

    def status_to_attr(self, status: str) -> int:
        if not curses.has_colors():
            return curses.A_NORMAL
        mapping = {
            "OK": curses.color_pair(1),
            "FAIL": curses.color_pair(2),
            "WARN": curses.color_pair(3),
            "SKIPPED": curses.color_pair(4),
            "UNCHECKED": curses.A_DIM,
        }
        return mapping.get(status, curses.A_NORMAL)

    def menu_option_attr(self, enabled: bool = True) -> int:
        attr = curses.A_BOLD
        if curses.has_colors():
            attr |= curses.color_pair(MENU_COLOR_PAIR)
        if not enabled:
            attr |= curses.A_DIM
        return attr

    # ----------------------------------------------------- tutorial helpers ---
    def _tutorial_context(self) -> Dict[str, str]:
        host = self.selected_host or "<host>"
        if self.selected_host:
            host_target = get_host_target(self.selected_host)
        else:
            host_target = "<host>"
        ssh_host = build_ssh_target(host_target)
        if CLUSTER_HOSTS:
            default_name, default_target = CLUSTER_HOSTS[0]
        else:
            default_name, default_target = ("<controller>", "<controller>")
        controller_name, controller_target = get_primary_controller(default_name, default_target)
        controller_ssh = build_ssh_target(controller_target)
        host_names = [name for name, _ in CLUSTER_HOSTS]
        host_loop = " ".join(shlex.quote(name) for name in host_names) or "<hosts>"
        repair_targets = self._order_hosts_for_repair(self._hosts_needing_repair())
        if not repair_targets:
            repair_targets = host_names
        repair_loop = " ".join(shlex.quote(name) for name in repair_targets) or "<hosts>"
        return {
            "host": host,
            "target": host_target,
            "ssh_host": ssh_host,
            "controller": controller_name,
            "controller_target": controller_target,
            "controller_ssh_target": controller_ssh,
            "host_loop": host_loop,
            "repair_loop": repair_loop,
            "host_list": ", ".join(host_names) or "<no hosts>",
            "log_file": LOG_FILE_DISPLAY,
            "ssh_user": SSH_USER or "root",
            "min_nodes": str(MIN_GFS_NODES),
        }

    def _current_tutorial_key(self, actions: List[Action]) -> Optional[str]:
        if not actions:
            return None
        index = min(max(self.selected_action_index, 0), len(actions) - 1)
        return actions[index][3]

    def _tutorial_commands(self, key: str, context: Dict[str, str]) -> List[str]:
        ssh_host = context["ssh_host"]
        controller_ssh = context["controller_ssh_target"]
        if key == "check_host":
            return [
                tutorial_ssh_line(ssh_host, "echo ok"),
                tutorial_ssh_line(ssh_host, "iscsiadm -m session"),
                tutorial_ssh_line(ssh_host, "multipath -ll"),
                tutorial_ssh_line(ssh_host, "mount | grep gfs2"),
                tutorial_ssh_line(ssh_host, "systemctl is-active corosync"),
                tutorial_ssh_line(controller_ssh, "pcs status"),
            ]
        if key == "check_all":
            host_loop = context["host_loop"]
            ssh_user = context["ssh_user"]
            return [
                f"for host in {host_loop}; do",
                f"  ssh {ssh_user}@$host 'echo ok'",
                f"  ssh {ssh_user}@$host 'iscsiadm -m session'",
                f"  ssh {ssh_user}@$host 'multipath -ll'",
                f"  ssh {ssh_user}@$host \"mount | grep gfs2\"",
                f"  ssh {ssh_user}@$host 'systemctl is-active corosync'",
                "done",
                tutorial_ssh_line(controller_ssh, "pcs status"),
            ]
        if key == "repair_host":
            return self._tutorial_commands_repair_host(context)
        if key == "repair_all":
            return self._tutorial_commands_repair_all(context)
        return []

    def _tutorial_commands_repair_host(self, context: Dict[str, str]) -> List[str]:
        ssh_host = context["ssh_host"]
        controller_ssh = context["controller_ssh_target"]
        host = context["host"]
        commands: List[str] = []
        for _, command in HOST_REPAIR_STEPS:
            commands.append(tutorial_ssh_line(ssh_host, command))
        for _, template in CONTROLLER_NODE_REPAIR_STEPS:
            formatted = template.format(host=host)
            commands.append(tutorial_ssh_line(controller_ssh, formatted))
        commands.append(tutorial_ssh_line(controller_ssh, "pcs status"))
        return commands

    def _tutorial_commands_repair_all(self, context: Dict[str, str]) -> List[str]:
        ssh_user = context["ssh_user"]
        controller_ssh = context["controller_ssh_target"]
        repair_loop = context["repair_loop"]
        commands: List[str] = [f"for host in {repair_loop}; do"]
        for _, command in HOST_REPAIR_STEPS:
            commands.append(f"  ssh {ssh_user}@$host {quote_for_shell(command)}")
        commands.append("done")
        commands.extend(
            [
                tutorial_ssh_line(controller_ssh, "pcs cluster start --all"),
                tutorial_ssh_line(controller_ssh, "pcs resource cleanup"),
                tutorial_ssh_line(controller_ssh, "pcs status"),
            ]
        )
        return commands

    def _tutorial_lines(self, actions: List[Action], width: int) -> List[str]:
        key = self._current_tutorial_key(actions)
        if not key:
            return []
        spec = TUTORIAL_CONTENT.get(key)
        if not spec:
            return []
        context = self._tutorial_context()
        lines: List[str] = [""]
        title = spec.get("title")
        if title:
            lines.append(f"Tutorial: {title.format(**context)}")
        reason = spec.get("reason")
        if reason:
            lines.extend(textwrap.wrap(f"Why: {reason.format(**context)}", width))
        commands = self._tutorial_commands(key, context)
        if commands:
            lines.append("Commands to run:")
            lines.extend(commands)
        notes = spec.get("notes")
        if notes:
            lines.extend(textwrap.wrap(f"Notes: {notes.format(**context)}", width))
        if key in {"repair_host", "repair_all"}:
            lines.extend(self._pcs_recovery_note_lines(width))
        return lines

    def _tutorial_line_attr(self, text: str) -> int:
        attr = curses.A_NORMAL
        stripped = text.strip()
        if not stripped:
            return attr
        if stripped.startswith("Tutorial:"):
            return curses.A_BOLD
        if stripped.startswith("Commands"):
            return self.menu_option_attr()
        if stripped.startswith("Why:") or stripped.startswith("Notes:"):
            return curses.A_DIM
        if text.startswith("  "):
            return curses.A_DIM
        return attr

    def prompt_for_password(self) -> None:
        prompt = "Enter SSH password (leave blank to use SSH keys only):"
        result = self._prompt_hidden_input(prompt)
        if result is None:
            self.post_message("Password entry canceled.")
            return
        if result:
            if set_ssh_password(result):
                self.post_message("SSH password stored for this session.")
            else:
                self.post_message("sshpass is not installed; password auth is unavailable.")
        else:
            set_ssh_password(None)
            self.post_message("SSH password cleared; falling back to SSH keys.")

    def _prompt_hidden_input(self, prompt: str) -> Optional[str]:
        height, width = self.stdscr.getmaxyx()
        win_width = min(width - 4, max(40, len(prompt) + 4))
        win_height = 5
        start_y = max(0, (height - win_height) // 2)
        start_x = max(0, (width - win_width) // 2)
        win = curses.newwin(win_height, win_width, start_y, start_x)
        win.keypad(True)
        win.border()
        prompt_text = prompt[: win_width - 2]
        win.addstr(1, 1, prompt_text)
        win.addstr(2, 1, "Enter=save  Esc=cancel")
        input_y = 3
        buffer: List[str] = []
        max_len = win_width - 2
        self._set_cursor_visible(True)
        try:
            while True:
                mask = "*" * len(buffer)
                visible = mask[-max_len:]
                win.addstr(input_y, 1, visible.ljust(max_len))
                win.move(input_y, 1 + len(visible))
                win.refresh()
                ch = win.getch()
                if ch in (10, 13, curses.KEY_ENTER):
                    return "".join(buffer)
                if ch == 27:  # ESC
                    return None
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if buffer:
                        buffer.pop()
                    continue
                if 0 <= ch <= 255:
                    char = chr(ch)
                    if char.isprintable() and len(buffer) < 512:
                        buffer.append(char)
        finally:
            self._set_cursor_visible(False)
            win.clear()
            del win
            self.stdscr.touchwin()
            self.stdscr.refresh()

    def _prompt_text_input(self, prompt: str, initial: str = "") -> Optional[str]:
        height, width = self.stdscr.getmaxyx()
        win_width = min(width - 4, max(40, len(prompt) + 4))
        win_height = 5
        start_y = max(0, (height - win_height) // 2)
        start_x = max(0, (width - win_width) // 2)
        win = curses.newwin(win_height, win_width, start_y, start_x)
        win.keypad(True)
        win.border()
        prompt_text = prompt[: win_width - 2]
        win.addstr(1, 1, prompt_text)
        win.addstr(2, 1, "Enter=save  Esc=cancel")
        input_y = 3
        buffer: List[str] = list(initial)
        max_len = win_width - 2
        self._set_cursor_visible(True)
        try:
            while True:
                visible = "".join(buffer)[-max_len:]
                win.addstr(input_y, 1, visible.ljust(max_len))
                win.move(input_y, 1 + len(visible))
                win.refresh()
                ch = win.getch()
                if ch in (10, 13, curses.KEY_ENTER):
                    return "".join(buffer)
                if ch == 27:  # ESC
                    return None
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if buffer:
                        buffer.pop()
                    continue
                if 0 <= ch <= 255:
                    char = chr(ch)
                    if char.isprintable() and len(buffer) < 512:
                        buffer.append(char)
        finally:
            self._set_cursor_visible(False)
            win.clear()
            del win
            self.stdscr.touchwin()
            self.stdscr.refresh()

    def _set_cursor_visible(self, visible: bool) -> None:
        try:
            curses.curs_set(1 if visible else 0)
        except curses.error:
            pass

    def _pcs_recovery_note_lines(self, width: int) -> List[str]:
        lines: List[str] = ["PCS recovery logic steps:"]
        for description, _ in CONTROLLER_NODE_REPAIR_STEPS:
            wrapped = textwrap.wrap(f"  - {description}", width)
            lines.extend(wrapped or [f"  - {description}"])
        cluster_header = "Cluster-wide cleanup after Repairs:"
        lines.extend(textwrap.wrap(cluster_header, width) or [cluster_header])
        for description, _ in CONTROLLER_REPAIR_STEPS:
            wrapped = textwrap.wrap(f"  - {description}", width)
            lines.extend(wrapped or [f"  - {description}"])
        gfs_line = "  - Re-enable and cleanup GFS2 clone resources, then rerun pcs status."
        lines.extend(textwrap.wrap(gfs_line, width) or [gfs_line])
        return lines

    # ------------------------------------------------------------ key input ---
    def handle_key(self, key: int) -> None:
        if key in (ord("q"), ord("Q")):
            self.request_exit()
            return
        if key == curses.KEY_RESIZE:
            return
        if key == curses.KEY_LEFT and self.focus == "actions":
            self.focus = "list"
            return
        if key == curses.KEY_RIGHT and self.focus == "list":
            actions = self.current_actions()
            if actions:
                self.focus = "actions"
                self.selected_action_index = min(self.selected_action_index, len(actions) - 1)
            else:
                self.post_message("No actions available for this selection.")
            return
        if key in (ord("p"), ord("P")):
            self.prompt_for_password()
            return
        if self.focus == "list":
            if key == curses.KEY_UP:
                self.selected_entry_index = max(0, self.selected_entry_index - 1)
                self.selected_action_index = 0
                return
            if key == curses.KEY_DOWN:
                entries = self.get_entries()
                if not entries:
                    return
                self.selected_entry_index = min(len(entries) - 1, self.selected_entry_index + 1)
                self.selected_action_index = 0
                return
            if key in (curses.KEY_ENTER, 10, 13):
                actions = self.current_actions()
                if actions:
                    self.focus = "actions"
                    self.selected_action_index = 0
                return
        else:  # focus == "actions"
            if key == curses.KEY_UP:
                self.selected_action_index = max(0, self.selected_action_index - 1)
                return
            if key == curses.KEY_DOWN:
                actions = self.current_actions()
                if actions:
                    self.selected_action_index = min(len(actions) - 1, self.selected_action_index + 1)
                return
            if key in (curses.KEY_ENTER, 10, 13):
                self.invoke_action(self.selected_action_index)
                return
        if key in (ord("c"), ord("C")):
            self.trigger_check_all()
            return
        if key in (ord("f"), ord("r")):
            self.trigger_repair_host()
            return
        if key in (ord("F"), ord("R")):
            self.trigger_repair_all()
            return

    # ---------------------------------------------------------- actions ---
    @property
    def selected_host(self) -> Optional[str]:
        entry_kind, entry_value = self.current_entry_info()
        if entry_kind == "host":
            return entry_value
        return None

    def get_entries(self) -> List[Tuple[str, Optional[str]]]:
        view = self.current_view
        entries: List[Tuple[str, Optional[str]]]
        if view == "main":
            entries = [("menu", key) for key, _, _ in MAIN_MENU]
        elif view == "cluster_health":
            entries = [("submenu", key) for key, _, _ in CLUSTER_HEALTH_MENU]
        elif view in {"node_status", "gfs_repair", "time_ntp"}:
            entries = [("host", name) for name, _ in CLUSTER_HOSTS]
            entries.append(("check_all", None))
            if self.check_all_completed:
                entries.append(("repair_all", None))
            entries.append(("back", None))
            entries.append(("exit", None))
        elif view == "health_summary":
            entries = [("summary", "health_summary"), ("export_summary", "health_summary"), ("back", None), ("exit", None)]
        elif view == "vm_inventory":
            entries = [("submenu", key) for key, _, _ in VM_INVENTORY_MENU] + [("exit", None)]
        elif view == "datastore":
            entries = [("submenu", key) for key, _, _ in DATASTORE_MENU] + [("exit", None)]
        elif view == "hosts_config":
            entries = [("submenu", key) for key, _, _ in HOST_CONFIG_MENU] + [("exit", None)]
        elif view == "logs_events":
            entries = [("submenu", key) for key, _, _ in LOGS_EVENTS_MENU] + [("exit", None)]
        elif view == "config_settings":
            entries = [("submenu", key) for key, _, _ in CONFIG_SETTINGS_MENU] + [("exit", None)]
        else:
            entries = [("exit", None)]
        return entries

    def current_entry_info(self) -> Tuple[str, Optional[str]]:
        entries = self.get_entries()
        if not entries:
            return ("none", None)
        if self.selected_entry_index < 0:
            self.selected_entry_index = 0
        if self.selected_entry_index >= len(entries):
            self.selected_entry_index = len(entries) - 1
        return entries[self.selected_entry_index]

    def current_actions(self) -> List[Action]:
        entry_kind, _ = self.current_entry_info()
        actions: List[Action] = []
        view = self.current_view
        entry_kind, entry_value = self.current_entry_info()

        # Main menu navigation.
        if entry_kind == "menu" and entry_value:
            if entry_value == "exit":
                actions.append(("Exit program (q)", True, self.request_exit, None))
            else:
                actions.append((f"Open {entry_value.replace('_', ' ')} menu", True, lambda v=entry_value: self.push_view(v), None))
        # Submenu navigation.
        elif entry_kind == "submenu" and entry_value:
            if entry_value == "back_main":
                actions.append(("Back to main menu", True, self.pop_view, None))
            elif view == "cluster_health" and entry_value in {"node_status", "gfs_repair", "time_ntp", "health_summary"}:
                actions.append((f"Open {entry_value.replace('_', ' ')}", True, lambda v=entry_value: self.push_view(v), None))
            else:
                actions.extend(self._actions_for_stub_section(view, entry_value))
        # Host-centric views reuse original logic.
        elif view in {"node_status", "gfs_repair", "time_ntp"} and entry_kind == "host" and self.selected_host:
            actions.append(("Check selected host", True, self.trigger_check_host, "check_host"))
            actions.append(("Repair selected host", True, self.trigger_repair_host, "repair_host"))
            if view == "time_ntp":
                actions.append(("Configure time server across hosts (TODO)", True, self.configure_time_server_stub, None))
        elif entry_kind == "check_all":
            actions.append(("Run check across all hosts", True, self.trigger_check_all, "check_all"))
            if view == "time_ntp":
                actions.append(("Run time sync check only (TODO)", True, self.check_time_only_stub, None))
        elif entry_kind == "repair_all":
            pending = self._hosts_needing_repair()
            if pending:
                actions.append(
                    (
                        f"Repair all unhealthy hosts ({len(pending)} pending)",
                        True,
                        self.trigger_repair_all,
                        "repair_all",
                    )
                )
            else:
                actions.append(("No repairs needed", False, None, None))
        elif entry_kind == "summary":
            actions.append(("Refresh health summary", True, self.trigger_check_all, "check_all"))
        elif entry_kind == "export_summary":
            actions.append(("Export health summary to file", True, self.export_health_summary, None))
        elif entry_kind == "back":
            actions.append(("Back", True, self.pop_view, None))
        elif entry_kind == "exit":
            actions.append(("Exit program (q)", True, self.request_exit, None))
        else:
            actions.extend(self._actions_for_stub_entry(view, entry_kind, entry_value))

        if self.selected_action_index >= len(actions):
            self.selected_action_index = max(0, len(actions) - 1)
        if not actions and self.focus == "actions":
            self.focus = "list"
        return actions

    def _actions_for_stub_section(self, view: str, key: str) -> List[Action]:
        actions: List[Action] = []
        if view == "vm_inventory":
            if key == "vm_list":
                actions.append(("List VMs across hosts (TODO)", True, self.vm_inventory_stub, None))
            elif key == "vm_manager":
                actions.extend(
                    [
                        ("Check VM manager status (TODO)", True, lambda: self.vm_manager_stub("status"), None),
                        ("Start VM manager (TODO)", True, lambda: self.vm_manager_stub("start"), None),
                        ("Stop VM manager (TODO)", True, lambda: self.vm_manager_stub("stop"), None),
                        ("Restart VM manager (TODO)", True, lambda: self.vm_manager_stub("restart"), None),
                    ]
                )
            elif key == "vm_actions":
                actions.append(("Choose VM and power on/off/reboot (TODO)", True, self.vm_actions_stub, None))
            elif key == "vm_alerts":
                actions.append(("Scan for VM usage alerts (TODO)", True, self.vm_alerts_stub, None))
        elif view == "datastore":
            if key == "ds_list":
                actions.append(("List datastores (TODO)", True, self.datastore_list_stub, None))
            elif key == "ds_health":
                actions.append(("Run datastore health checks (TODO)", True, self.datastore_health_stub, None))
            elif key == "ds_cleanup":
                actions.append(("Suggest storage cleanup (TODO)", True, self.datastore_cleanup_stub, None))
            elif key == "ds_export":
                actions.append(("Export storage summary (TODO)", True, self.datastore_export_stub, None))
        elif view == "hosts_config":
            if key == "net_health":
                actions.append(("Check network health (TODO)", True, self.network_health_stub, None))
            elif key == "os_patch":
                actions.append(("Check OS/patch status (TODO)", True, self.os_patch_stub, None))
            elif key == "config_drift":
                actions.append(("Check config drift (TODO)", True, self.config_drift_stub, None))
            elif key == "service_control":
                actions.append(("Service control across hosts (TODO)", True, self.service_control_stub, None))
        elif view == "logs_events":
            if key == "cluster_logs":
                actions.append(("View recent cluster logs (TODO pager)", True, self.cluster_logs_stub, None))
            elif key == "backups":
                actions.append(("Check backup/snapshot status (TODO)", True, self.backup_checks_stub, None))
            elif key == "export_logs":
                actions.append(("Export logs (TODO)", True, self.export_logs_stub, None))
        elif view == "config_settings":
            if key == "default_time_server":
                actions.append(("Set default time server", True, self.set_default_time_server, None))
            elif key == "alert_thresholds":
                actions.append(("Edit alert thresholds (TODO)", True, self.alert_thresholds_stub, None))
            elif key == "tui_prefs":
                actions.append(("Edit TUI preferences (TODO)", True, self.tui_prefs_stub, None))
            elif key == "help_about":
                actions.append((f"Show help/about ({APP_VERSION})", True, self.help_about_stub, None))
        return actions

    def _actions_for_stub_entry(self, view: str, entry_kind: str, entry_value: Optional[str]) -> List[Action]:
        actions: List[Action] = []
        # Default back mapping for submenu back rows.
        if entry_kind == "submenu" and entry_value == "back_main":
            actions.append(("Back to main menu", True, self.pop_view, None))
        return actions

    # ------------------------------------------------------ stub handlers ---
    def _run_stub_job(self, title: str, note: str) -> None:
        """Queue a stub job with a TODO note."""

        def worker() -> None:
            # TODO: Replace this stub with real implementation.
            self.queue.put(("message", f"{title}: TODO - {note}"))

        self.run_worker(title, worker)

    def vm_inventory_stub(self) -> None:
        self._run_stub_job("VM inventory", "Integrate VM inventory commands/API per host.")

    def vm_manager_stub(self, action: str = "status") -> None:
        self._run_stub_job(
            f"VM manager {action}",
            "Add service name and control commands for VM manager (start/stop/restart/status).",
        )

    def vm_actions_stub(self) -> None:
        self._run_stub_job("VM actions", "Select VM then power on/off/reboot via hypervisor tooling.")

    def vm_alerts_stub(self) -> None:
        self._run_stub_job("VM alerts", "Scan for high CPU/RAM or long-term powered-off VMs (TODO).")

    def datastore_list_stub(self) -> None:
        self._run_stub_job("Datastore listing", "Call Verge/storage API to list datastores (TODO).")

    def datastore_health_stub(self) -> None:
        self._run_stub_job("Datastore health", "Check free/used, mounts, and thresholds (TODO).")

    def datastore_cleanup_stub(self) -> None:
        self._run_stub_job("Datastore cleanup", "Suggest cleanup for old snapshots and near-full datastores (TODO).")

    def datastore_export_stub(self) -> None:
        self._run_stub_job("Datastore export", "Export datastore summary to CSV/text (TODO).")

    def network_health_stub(self) -> None:
        self._run_stub_job("Network health", "Add bond/VLAN/bridge status commands (TODO).")

    def os_patch_stub(self) -> None:
        self._run_stub_job("OS/patch status", "Collect OS version, kernel, and pending updates per node (TODO).")

    def config_drift_stub(self) -> None:
        self._run_stub_job("Config drift", "Compare nodes against baseline configuration (TODO).")

    def service_control_stub(self) -> None:
        self._run_stub_job("Service control", "List and manage important services across hosts (TODO).")

    def cluster_logs_stub(self) -> None:
        self._run_stub_job("Cluster logs", "Implement pager/filter for cluster logs (TODO).")

    def backup_checks_stub(self) -> None:
        self._run_stub_job("Backup/snapshot checks", "Check backup job status and snapshot times (TODO).")

    def export_logs_stub(self) -> None:
        self._run_stub_job("Export logs", "Dump selected logs to a file for sharing (TODO).")

    def configure_time_server_stub(self) -> None:
        self._run_stub_job(
            "Configure time server",
            "Push configured NTP server to all hosts (TODO: chrony/ntpd commands).",
        )

    def check_time_only_stub(self) -> None:
        self._run_stub_job("Time check", "Run time-only drift/sync checks (TODO dedicated flow).")

    def alert_thresholds_stub(self) -> None:
        self._run_stub_job("Alert thresholds", "Persist disk/CPU thresholds to config (TODO).")

    def tui_prefs_stub(self) -> None:
        self._run_stub_job("TUI preferences", "Persist layout/color preferences without changing visuals (TODO).")

    def help_about_stub(self) -> None:
        note = f"VME Cluster TUI {APP_VERSION} built on cluster_tui logic."
        self._run_stub_job("Help/About", note)

    def set_default_time_server(self) -> None:
        current = self.config.get("default_time_server", "")
        result = self._prompt_text_input("Enter default time server (e.g., pool.ntp.org):", current)
        if result is None:
            self.post_message("Default time server unchanged.")
            return
        self.config["default_time_server"] = result.strip()
        save_config(self.config)
        # TODO: push this time server to chrony/ntpd across hosts.
        self.post_message(f"Default time server set to '{self.config['default_time_server']}' (config saved).")

    def export_health_summary(self) -> None:
        path = SCRIPT_PATH.with_name(f"vme-health-summary-{datetime.now():%Y%m%d-%H%M%S}.txt")
        summary = self._health_summary_text()
        try:
            path.write_text(summary)
            self.post_message(f"Wrote health summary to {path}")
        except Exception as exc:  # pragma: no cover - defensive
            self.post_message(f"Failed to write health summary: {exc}")

    def _health_summary_text(self) -> str:
        lines: List[str] = []
        lines.append(f"VME Cluster Health Summary ({datetime.now():%Y-%m-%d %H:%M:%S})")
        lines.append(f"Hosts: {', '.join(name for name, _ in CLUSTER_HOSTS)}")
        lines.append("")
        for name, _ in CLUSTER_HOSTS:
            status = self.host_statuses.get(name) or HostStatus(host=name, checks=create_default_checks())
            lines.append(f"{name}: {status.overall_status()}")
            for check in status.checks:
                lines.append(f"  - {check.name}: {check.status} ({check.summary})")
            lines.append("")
        warnings = self._storage_quorum_warnings()
        if warnings:
            lines.append("Storage/Quorum warnings:")
            lines.extend(f"- {w}" for w in warnings)
            lines.append("")
        lines.append(f"Log file: {LOG_FILE_DISPLAY}")
        return "\n".join(lines)

    def invoke_action(self, action_index: int) -> None:
        actions = self.current_actions()
        if not actions:
            return
        action_index = max(0, min(action_index, len(actions) - 1))
        label, enabled, handler, _ = actions[action_index]
        if not enabled or handler is None:
            self.post_message(f"Action '{label}' is not available right now.")
            return
        handler()

    def trigger_check_host(self) -> None:
        host = self.selected_host
        if not host:
            self.post_message("No host selected")
            return
        self.run_worker(f"Checking {host}", lambda: self._check_host_worker(host))

    def trigger_check_all(self) -> None:
        if not CLUSTER_HOSTS:
            self.post_message("No hosts configured")
            return
        self.check_all_completed = False
        self.run_worker("Checking all hosts", self._check_all_worker)

    def trigger_repair_host(self) -> None:
        host = self.selected_host
        if not host:
            self.post_message("No host selected")
            return
        self.run_worker(f"Repairing {host}", lambda: self._repair_host_worker(host))

    def trigger_repair_all(self) -> None:
        if not CLUSTER_HOSTS:
            self.post_message("No hosts configured")
            return
        if not self.check_all_completed:
            self.post_message("Run Check All before Fix All.")
            return
        hosts_to_fix = self._hosts_needing_repair()
        if not hosts_to_fix:
            self.post_message("All hosts appear healthy; Fix All skipped.")
            return
        ordered_hosts = self._order_hosts_for_repair(hosts_to_fix)
        self.run_worker(
            "Repairing entire cluster",
            self._repair_all_worker(ordered_hosts),
        )

    def request_exit(self) -> None:
        self.running = False

    # ------------------------------------------------------------ workers ---
    def run_worker(self, description: str, func) -> None:
        job_id = self._job_seq
        self._job_seq += 1
        self.queue.put(("job_start", (job_id, description)))

        def wrapper() -> None:
            self.queue.put(("message", f"{description} started"))
            try:
                func()
                self.queue.put(("message", f"{description} finished"))
            except Exception as exc:  # pragma: no cover - defensive
                self.queue.put(("message", f"{description} failed: {exc}"))
            finally:
                self.queue.put(("job_end", job_id))

        worker = threading.Thread(target=wrapper, daemon=True)
        worker.start()

    def _check_host_worker(self, host: str) -> None:
        status = perform_host_checks(host)
        self.queue.put(("host_status", status))
        self.queue.put(("message", f"Checks for {host} completed with {status.overall_status()}"))

    def _check_all_worker(self) -> None:
        for name, _ in CLUSTER_HOSTS:
            status = perform_host_checks(name)
            self.queue.put(("host_status", status))
            self.queue.put(("message", f"Checks for {name} completed with {status.overall_status()}"))
        self.queue.put(("check_all_complete", None))

    def _repair_host_worker(self, host: str) -> None:
        status = repair_host_and_check(host)
        self.queue.put(("host_status", status))
        self.queue.put(("message", f"Repair for {host} completed with {status.overall_status()}"))

    def _repair_all_worker(self, hosts: List[str]):
        def worker() -> None:
            updated_statuses: Dict[str, HostStatus] = {}
            for host in hosts:
                status = repair_host_and_check(host)
                updated_statuses[host] = status
                self.queue.put(("host_status", status))
                self.queue.put(("message", f"Repair for {host} completed with {status.overall_status()}"))
            if hosts:
                fallback_name = hosts[0]
                fallback_target = get_host_target(fallback_name)
                controller_name, controller_target = get_primary_controller(fallback_name, fallback_target)
                summary, details = run_cluster_level_repairs(controller_target)
                controller_status = updated_statuses.get(controller_name)
                if controller_status:
                    controller_status.add_repair_entry(summary, details)
                    self.queue.put(("host_status", controller_status))
                self.queue.put(("message", summary))
            self.queue.put(("message", "Repairs finished; running full cluster check"))
            self.queue.put(("check_all_pending", None))
            self._check_all_worker()
            self.queue.put(("repair_all_complete", None))

        return worker

    def process_queue(self) -> None:
        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "host_status":
                status = payload  # type: ignore[assignment]
                if isinstance(status, HostStatus):
                    self.host_statuses[status.host] = status
            elif kind == "message":
                message = str(payload)
                self.post_message(message)
            elif kind == "check_all_complete":
                self.check_all_completed = True
            elif kind == "check_all_pending":
                self.check_all_completed = False
            elif kind == "repair_all_complete":
                pass
            elif kind == "job_start":
                job_id, description = payload  # type: ignore[misc]
                self._active_jobs[int(job_id)] = str(description)
            elif kind == "job_end":
                job_id = int(payload)  # type: ignore[arg-type]
                self._active_jobs.pop(job_id, None)

    def post_message(self, text: str) -> None:
        logger.info("UI message: %s", text)
        self.messages.append(text)

    def _hosts_needing_repair(self) -> List[str]:
        hosts: List[str] = []
        for name, _ in CLUSTER_HOSTS:
            status = self.host_statuses.get(name)
            if status and status.overall_status() != "OK":
                hosts.append(name)
        return hosts

    def _storage_quorum_warnings(self) -> List[str]:
        warnings: List[str] = []
        if not self.host_statuses:
            return warnings

        hosts_with_good_storage: List[str] = []
        hosts_without_iscsi: List[str] = []

        for name, _ in CLUSTER_HOSTS:
            host_status = self.host_statuses.get(name)
            if not host_status:
                hosts_without_iscsi.append(name)
                continue
            try:
                iscsi = host_status.get_check("iSCSI")
                gfs = host_status.get_check("GFS2")
            except KeyError:
                hosts_without_iscsi.append(name)
                continue

            iscsi_ok = iscsi.status == "OK"
            gfs_ok = gfs.status == "OK"

            if iscsi_ok and gfs_ok:
                hosts_with_good_storage.append(name)

            if not iscsi_ok:
                hosts_without_iscsi.append(name)

        if len(hosts_with_good_storage) < MIN_GFS_NODES:
            warnings.append(
                f"WARNING: Only {len(hosts_with_good_storage)} of {len(CLUSTER_HOSTS)} hosts "
                f"have healthy iSCSI+GFS2; VME GFS2 requires at least {MIN_GFS_NODES} nodes."
            )

        if hosts_without_iscsi:
            hostlist = ", ".join(hosts_without_iscsi)
            warnings.append(f"Storage WARNING: No healthy iSCSI session detected on: {hostlist}")

        return warnings

    def _pcs_issue_hosts(self) -> List[str]:
        failures: List[str] = []
        for name, _ in CLUSTER_HOSTS:
            status = self.host_statuses.get(name)
            if not status:
                continue
            try:
                pacemaker = status.get_check("Pacemaker")
            except KeyError:
                continue
            if pacemaker.status != "OK":
                failures.append(name)
        return failures

    def _pcs_recovery_lines(self, width: int) -> List[str]:
        if not CLUSTER_HOSTS:
            return []
        lines: List[str] = []
        failing = self._pcs_issue_hosts()
        if failing:
            text = f"PCS status issues detected on: {', '.join(failing)}"
        else:
            text = "PCS status currently OK across all hosts."
        lines.extend(textwrap.wrap(text, width) or [text])
        lines.append("PCS recovery logic:")
        host_intro = "Per-host repair also runs these controller steps when Pacemaker reports trouble:"
        lines.extend(textwrap.wrap(host_intro, width))
        for description, _ in CONTROLLER_NODE_REPAIR_STEPS:
            lines.append(f"  - {description}")
        cluster_intro = "Repair All finishes by applying cluster-wide cleanup:"
        lines.extend(textwrap.wrap(cluster_intro, width))
        for description, _ in CONTROLLER_REPAIR_STEPS:
            lines.append(f"  - {description}")
        lines.append("  - Re-enable/cleanup any detected GFS2 clone resources.")
        lines.append("  - Verify Corosync and Pacemaker via pcs status.")
        logic_line = (
            "  - Branching: count_down>=2 -> full sync/reload/cleanup/restart; "
            "count_down==1 -> partial cleanup/restart; count_down==0 -> storage check then noop if healthy."
        )
        lines.extend(textwrap.wrap(logic_line, width) or [logic_line])
        return lines

    def _order_hosts_for_repair(self, hosts: List[str]) -> List[str]:
        def priority(host: str) -> Tuple[int, int]:
            status = self.host_statuses.get(host)
            idx = host_index(host)
            base_index = idx if idx >= 0 else 0
            if not status:
                return (3, base_index)

            def check_state(name: str) -> str:
                try:
                    return status.get_check(name).status
                except KeyError:
                    return "UNCHECKED"

            if check_state("SSH") != "OK":
                return (0, base_index)
            if check_state("iSCSI") != "OK":
                return (1, base_index)
            if check_state("GFS2") != "OK":
                return (2, base_index)
            return (3, base_index)

        return sorted(hosts, key=priority)

    def busy_status_text(self) -> str:
        if not self._active_jobs:
            return "Status: Idle"
        self._spinner_index = (self._spinner_index + 1) % len(self.SPINNER_FRAMES)
        spinner = self.SPINNER_FRAMES[self._spinner_index]
        first_desc = next(iter(self._active_jobs.values()))
        extra = len(self._active_jobs) - 1
        suffix = f" (+{extra} more)" if extra > 0 else ""
        return f"{spinner} Working: {first_desc}{suffix}"


def main() -> None:
    global CLUSTER_HOSTS, HOST_TARGETS
    cli_hosts = parse_cli_hosts(sys.argv[1:])
    if cli_hosts:
        CLUSTER_HOSTS = cli_hosts
    else:
        default_hosts = parse_cli_hosts(DEFAULT_HOSTS_LINE.split()) if DEFAULT_HOSTS_LINE.strip() else []
        CLUSTER_HOSTS = default_hosts

    if not CLUSTER_HOSTS:
        print("Usage: python3 cluster_tui.py host1,10.10.10.10 host2,10.10.10.11 ...")
        print("Or edit DEFAULT_HOSTS_LINE at the top of the script.")
        sys.exit(1)

    total_nodes = len(CLUSTER_HOSTS)
    if total_nodes < 3 or total_nodes > 10:
        print(f"Cluster recovery expects between 3 and 10 nodes; detected {total_nodes}.")
        sys.exit(1)

    HOST_TARGETS = {name: target for name, target in CLUSTER_HOSTS}

    config = load_config()

    def runner(stdscr: Any) -> None:
        ui = VMEClusterUI(stdscr, config=config)
        ui.run()

    curses.wrapper(runner)


if __name__ == "__main__":
    main()

# Verification / Test (Ubuntu 24.04):
#   python3 -m py_compile cluster_tui.py
#   python3 cluster_tui.py e1,10.10.10.5 e2,10.10.10.6 e3,10.10.10.7
#   pcs status --full
#   chronyc tracking
#   timedatectl show -p NTPSynchronized -p SystemClockSynchronized
