#!/usr/bin/env python3
"""Simple curses-based cluster health and repair helper."""

from __future__ import annotations

import curses
import logging
import queue
import shlex
import shutil
import subprocess
import sys
import textwrap
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

# -------------------------------------------------------------------------
# SSH configuration
SSH_USER = "root"
SSH_PASSWORD = ""  # leave empty for key auth; password mode requires sshpass (not installed by default)
# -------------------------------------------------------------------------

# Edit this single line with "host host" or "name,ip" tokens to change built-in hosts.
DEFAULT_HOSTS_LINE = "e1 e2 e3"

# CLUSTER_HOSTS populated at runtime
CLUSTER_HOSTS: List[Tuple[str, str]] = []
HOST_TARGETS: Dict[str, str] = {}

MENU_COLOR_PAIR = 5
TITLE_COLOR_PAIR = 6
MIN_GFS_NODES = 3

APP_VERSION = "v2025.02.17"

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_NAME = SCRIPT_PATH.stem
LOG_FILE_PATH = SCRIPT_PATH.with_name(f"{SCRIPT_NAME}-{datetime.now():%Y%m%d}.log")
LOG_FILE_DISPLAY = str(LOG_FILE_PATH)

logger = logging.getLogger("cluster_tui")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_FILE_PATH, mode="a")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


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


CHECK_NAMES = ["SSH", "iSCSI", "GFS2", "Corosync", "Pacemaker"]
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
    ("Start cluster everywhere", "pcs cluster start --all"),
    ("Cleanup failed resources", "pcs resource cleanup"),
]

Action = Tuple[str, bool, Optional[Callable[[], None]], Optional[str]]
SSH_COMMON_FLAGS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
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


def perform_host_checks(host: str, target: Optional[str] = None) -> HostStatus:
    """Run the health check chain for HOST and return a populated HostStatus."""
    resolved_target = target or get_host_target(host)
    logger.info("Starting health checks for %s (%s)", host, resolved_target)
    status = HostStatus(host=host, checks=create_default_checks(), last_run_time=datetime.now())

    ssh_result = check_ssh(host, resolved_target)
    status.set_check("SSH", ssh_result.status, ssh_result.summary, ssh_result.output)
    if ssh_result.status != "OK":
        for later in ("iSCSI", "GFS2", "Corosync", "Pacemaker"):
            status.set_check(
                later,
                "SKIPPED",
                "Skipped because SSH failed",
                "",
            )
        return status

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


def detect_gfs2_clone_resources(controller_target: str) -> List[str]:
    exit_code, stdout, stderr = run_remote_command(controller_target, "pcs status", timeout=60)
    # run_remote_command already logs details; proceed even if pcs status fails.
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
        clone_name = remainder.split()[0].strip("[]:,")
        if not clone_name.lower().startswith("gfs"):
            continue
        clone_name = clone_name.rstrip(":")
        if clone_name and clone_name not in seen:
            clones.append(clone_name)
            seen.add(clone_name)
    return clones


def repair_gfs2_resources(controller_target: str) -> Tuple[bool, str]:
    clone_resources = detect_gfs2_clone_resources(controller_target)
    if not clone_resources:
        return True, "No GFS2 clone resources detected via pcs status"

    steps: List[Tuple[str, str]] = []
    for clone in clone_resources:
        steps.append((f"Enable GFS2 clone {clone}", f"pcs resource enable {clone}"))
        steps.append((f"Cleanup GFS2 clone {clone}", f"pcs resource cleanup {clone}"))

    success, step_details = run_step_sequence(controller_target, steps, timeout=90)
    header = f"Detected GFS2 clone resources: {', '.join(clone_resources)}"
    combined_details = "\n\n".join(part for part in (header, step_details) if part).strip()
    return success, combined_details


def run_cluster_level_repairs(controller_target: str) -> Tuple[str, str]:
    controller_success, controller_details = run_step_sequence(
        controller_target, CONTROLLER_REPAIR_STEPS, timeout=90
    )
    gfs_success, gfs_details = repair_gfs2_resources(controller_target)

    summary_parts = [
        "Cluster level repair completed" if controller_success else "Cluster level repair reported errors",
        "GFS2 repair completed" if gfs_success else "GFS2 repair reported errors",
    ]
    details = "\n\n".join(part for part in (controller_details, gfs_details) if part).strip()
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


class ClusterUI:
    SPINNER_FRAMES = "|/-\\"

    def __init__(self, stdscr: Any) -> None:
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
        title = f"Cluster TUI {APP_VERSION} | Log: {LOG_FILE_DISPLAY}"
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
        title = "Cluster Nodes"
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
            attr = curses.A_NORMAL
            if entry_kind == "host" and entry_value:
                status = self.host_statuses[entry_value].overall_status()
                entry_text = f"{status:<9} {entry_value}"
                attr |= self.status_to_attr(status)
            elif entry_kind == "check_all":
                entry_text = ">> Check all hosts"
                attr |= self.menu_option_attr()
            elif entry_kind == "repair_all":
                count = len(self._hosts_needing_repair())
                entry_text = f">> Repair all hosts ({count} pending)" if count else ">> Repair all hosts"
                attr |= self.menu_option_attr()
            elif entry_kind == "exit":
                entry_text = ">> Exit (q)"
                attr |= self.menu_option_attr()
            else:
                entry_text = "--"
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
        else:
            self.safe_addstr(detail_start, padding_x, "No details available.")

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
        entries: List[Tuple[str, Optional[str]]] = [("host", name) for name, _ in CLUSTER_HOSTS]
        entries.append(("check_all", None))
        if self.check_all_completed:
            entries.append(("repair_all", None))
        entries.append(("exit", None))
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
        if entry_kind == "host" and self.selected_host:
            actions.append(("Check selected host", True, self.trigger_check_host, "check_host"))
            actions.append(("Repair selected host", True, self.trigger_repair_host, "repair_host"))
        elif entry_kind == "check_all":
            actions.append(("Run check across all hosts", True, self.trigger_check_all, "check_all"))
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
        elif entry_kind == "exit":
            actions.append(("Exit program (q)", True, self.request_exit, None))
        if self.selected_action_index >= len(actions):
            self.selected_action_index = max(0, len(actions) - 1)
        if not actions and self.focus == "actions":
            self.focus = "list"
        return actions

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

    HOST_TARGETS = {name: target for name, target in CLUSTER_HOSTS}

    def runner(stdscr: Any) -> None:
        ui = ClusterUI(stdscr)
        ui.run()

    curses.wrapper(runner)


if __name__ == "__main__":
    main()
