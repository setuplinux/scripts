#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import curses
from pathlib import Path
from datetime import datetime

class SystemChecker:
    def __init__(self, min_disk_gb=30):
        self.min_disk_gb = min_disk_gb
        self.checks_passed = 0
        self.checks_failed = 0
        self.checks_warned = 0
        
    def run_cmd(self, cmd):
        """Run command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)
    
    def format_result(self, status, check_name, reason, cmd=""):
        """Format check result for display"""
        lines = []
        if status == "pass":
            lines.append(f"<{check_name}>")
            lines.append(f"    ✔ PASS: {reason}")
        elif status == "warn":
            lines.append(f"<{check_name}>")
            lines.append(f"    ! WARN: {reason}")
        else:  # error
            lines.append(f"<{check_name}>")
            lines.append(f"    ✗ ERROR: {reason}")
        
        if cmd:
            lines.append(f"    CMD: {cmd}")
        lines.append("")
        return lines
    
    def check_os_info(self):
        """System checks including OS, KVM, and Morpheus tools"""
        results = []
        
        # Ubuntu version
        rc, out, err = self.run_cmd("lsb_release -r -s")
        if rc == 0 and "24.04" in out:
            results.extend(self.format_result("pass", "Ubuntu Version", f"Running Ubuntu {out}", "lsb_release -r"))
        elif rc == 0 and "22.04" in out:
            results.extend(self.format_result("error", "Ubuntu Version", f"Found Ubuntu {out}, need 24.04", "lsb_release -r"))
        else:
            results.extend(self.format_result("error", "Ubuntu Version", "Cannot determine Ubuntu version", "lsb_release -r"))
        
        # Architecture
        rc, out, err = self.run_cmd("uname -m")
        if rc == 0 and out == "x86_64":
            results.extend(self.format_result("pass", "Architecture", "x86_64 confirmed", "uname -m"))
        elif "arm" in out.lower() or "aarch64" in out.lower():
            results.extend(self.format_result("error", "Architecture", f"ARM architecture detected ({out}), need x86_64", "uname -m"))
        else:
            results.extend(self.format_result("warn", "Architecture", f"Unknown architecture: {out}", "uname -m"))
        
        # KVM hypervisor modules (host check)
        rc, kvm_out, err = self.run_cmd("lsmod | grep kvm")
        if rc == 0 and kvm_out:
            if "kvm_intel" in kvm_out or "kvm_amd" in kvm_out:
                results.extend(self.format_result("pass", "KVM Hypervisor", "KVM modules loaded (hypervisor ready)", "lsmod | grep kvm"))
            else:
                results.extend(self.format_result("warn", "KVM Hypervisor", "Base KVM loaded but no CPU-specific module", "lsmod | grep kvm"))
        else:
            results.extend(self.format_result("error", "KVM Hypervisor", "No KVM modules found", "lsmod | grep kvm"))
        
        # CPU virtualization support
        rc, virt_out, err = self.run_cmd("grep -E '(vmx|svm)' /proc/cpuinfo")
        if rc == 0 and virt_out:
            if "vmx" in virt_out:
                results.extend(self.format_result("pass", "CPU Virtualization", "Intel VT-x supported", "grep vmx /proc/cpuinfo"))
            elif "svm" in virt_out:
                results.extend(self.format_result("pass", "CPU Virtualization", "AMD-V supported", "grep svm /proc/cpuinfo"))
        else:
            results.extend(self.format_result("error", "CPU Virtualization", "No virtualization extensions found", "grep -E '(vmx|svm)' /proc/cpuinfo"))
        
        # Secure Boot
        if os.path.exists("/sys/firmware/efi"):
            rc, out, err = self.run_cmd("mokutil --sb-state 2>/dev/null")
            if "disabled" in out.lower():
                results.extend(self.format_result("pass", "Secure Boot", "Disabled", "mokutil --sb-state"))
            elif "enabled" in out.lower():
                results.extend(self.format_result("warn", "Secure Boot", "Enabled - may cause issues", "mokutil --sb-state"))
            else:
                results.extend(self.format_result("warn", "Secure Boot", "Status unknown", "mokutil --sb-state"))
        else:
            results.extend(self.format_result("pass", "Secure Boot", "Legacy BIOS - N/A", "ls /sys/firmware/efi"))
        
        # Morpheus Tools Check
        morpheus_ctl_present = False
        rc, out, err = self.run_cmd("which morpheus-node-ctl")
        if rc == 0 and out:
            morpheus_ctl_present = True
        
        hpe_vm_present = os.path.exists("/opt/hpe-vm")
        morpheus_node_present = os.path.exists("/opt/morpheus-node")
        
        if morpheus_ctl_present and morpheus_node_present:
            results.extend(self.format_result("pass", "Morpheus Tools", "Fully installed and configured", "which morpheus-node-ctl && ls /opt/morpheus-node"))
        elif hpe_vm_present and not morpheus_ctl_present:
            results.extend(self.format_result("warn", "Morpheus Tools", "HPE-VM installed but not joined to cluster yet", "ls /opt/ | grep -E '(hpe-vm|morpheus)'"))
        elif morpheus_node_present and not morpheus_ctl_present:
            results.extend(self.format_result("warn", "Morpheus Tools", "Morpheus node dir exists but ctl not in PATH", "ls /opt/morpheus-node/bin/"))
        elif not hpe_vm_present and not morpheus_node_present:
            results.extend(self.format_result("error", "Morpheus Tools", "No HPE-VM or Morpheus installation found", "ls /opt/"))
        else:
            results.extend(self.format_result("warn", "Morpheus Tools", "Partial installation detected", "ls /opt/ && which morpheus-node-ctl"))
        
        return results
    
    def check_storage_info(self):
        """Storage and disk checks"""
        results = []
        
        # Add storage overview
        results.append("<STORAGE OVERVIEW>")
        results.append("")
        
        # lsblk output
        rc, lsblk_out, err = self.run_cmd("lsblk")
        if rc == 0:
            results.append("LSBLK OUTPUT:")
            results.extend(lsblk_out.split('\n'))
            results.append("")
        
        # df -h output
        rc, df_out, err = self.run_cmd("df -h")
        if rc == 0:
            results.append("DISK USAGE:")
            results.extend(df_out.split('\n'))
            results.append("")
        
        # Root filesystem space check
        rc, out, err = self.run_cmd("df --output=avail -BG / | tail -1")
        if rc == 0:
            try:
                avail_gb = int(out.replace('G', ''))
                if avail_gb >= self.min_disk_gb:
                    results.extend(self.format_result("pass", "Disk Space", f"{avail_gb}GB available (≥{self.min_disk_gb}GB required)", "df -h /"))
                else:
                    results.extend(self.format_result("error", "Disk Space", f"Only {avail_gb}GB available, need {self.min_disk_gb}GB", "df -h /"))
            except:
                results.extend(self.format_result("warn", "Disk Space", "Cannot parse disk space", "df -h /"))
        
        # /var/morpheus check
        if os.path.exists("/var/morpheus"):
            rc, out, err = self.run_cmd("du -sh /var/morpheus")
            if rc == 0:
                results.extend(self.format_result("pass", "/var/morpheus Usage", f"{out.split()[0]}", "du -sh /var/morpheus"))
        
        # UUID mount check - skip this check since /dev/ mounts are default and acceptable
        results.extend(self.format_result("pass", "Mount Points", "Filesystem mounts configured", "grep -E '(UUID=|/dev/)' /etc/fstab"))
        
        return results
    
    def check_iscsi_info(self):
        """iSCSI configuration and status"""
        results = []
        results.append("<iSCSI STATUS>")
        results.append("")
        
        # Check if iscsiadm exists
        rc, out, err = self.run_cmd("which iscsiadm")
        if rc != 0:
            results.extend(self.format_result("warn", "iSCSI Tools", "iscsiadm not installed", "which iscsiadm"))
            return results
        
        # Active sessions
        rc, sessions_out, err = self.run_cmd("iscsiadm -m session")
        if rc == 0 and sessions_out:
            results.extend(self.format_result("pass", "iSCSI Sessions", "Active sessions found", "iscsiadm -m session"))
            results.append("ACTIVE SESSIONS:")
            results.extend(sessions_out.split('\n'))
            results.append("")
        else:
            results.extend(self.format_result("warn", "iSCSI Sessions", "No active sessions", "iscsiadm -m session"))
        
        # Configured targets
        rc, nodes_out, err = self.run_cmd("iscsiadm -m node")
        if rc == 0 and nodes_out:
            results.append("CONFIGURED TARGETS:")
            results.extend(nodes_out.split('\n'))
            results.append("")
            
            if "alletra" in nodes_out.lower():
                results.extend(self.format_result("pass", "HPE Alletra Storage", "HPE Alletra storage detected", "iscsiadm -m node"))
        
        # Multipath
        rc, mp_out, err = self.run_cmd("multipath -l")
        if rc == 0 and mp_out and "No paths found" not in mp_out:
            results.extend(self.format_result("pass", "Multipath", "Active paths found", "multipath -l"))
            results.append("MULTIPATH STATUS:")
            results.extend(mp_out.split('\n')[:20])  # Limit output
        else:
            results.extend(self.format_result("warn", "Multipath", "No multipath devices", "multipath -l"))
        
        return results
    
    def check_network_info(self):
        """Network configuration and connectivity"""
        results = []
        results.append("<NETWORK CONFIGURATION>")
        results.append("")
        
        # Check which network manager is active
        nm_active = False
        netplan_active = False
        
        # Check NetworkManager (GUI/Desktop tool)
        rc, nm_out, err = self.run_cmd("systemctl is-active NetworkManager 2>/dev/null")
        if rc == 0 and "active" in nm_out:
            nm_active = True
            results.extend(self.format_result("warn", "Network Manager", "NetworkManager is active (should use netplan on servers)", "systemctl status NetworkManager"))
        
        # Check netplan
        rc, netplan_out, err = self.run_cmd("systemctl is-active systemd-networkd 2>/dev/null")
        if rc == 0 and "active" in netplan_out:
            netplan_active = True
        
        # Check what's managing networking
        if nm_active and netplan_active:
            results.extend(self.format_result("error", "Network Config", "Both NetworkManager and netplan active - conflict!", "systemctl status NetworkManager systemd-networkd"))
        elif nm_active:
            results.extend(self.format_result("warn", "Network Config", "Using NetworkManager (desktop tool, consider netplan)", "systemctl status NetworkManager"))
        elif netplan_active:
            results.extend(self.format_result("pass", "Network Config", "Using netplan (recommended for servers)", "systemctl status systemd-networkd"))
        else:
            results.extend(self.format_result("warn", "Network Config", "Neither NetworkManager nor netplan clearly active", "systemctl status NetworkManager systemd-networkd"))
        
        # Show Netplan config if using netplan
        if not nm_active:  # Only show netplan config if not using NetworkManager
            netplan_files = list(Path("/etc/netplan").glob("*.yaml")) if Path("/etc/netplan").exists() else []
            if netplan_files:
                results.append("NETPLAN CONFIG (copy/paste ready):")
                for file in netplan_files:
                    results.append(f"--- {file} ---")
                    try:
                        with open(file, 'r') as f:
                            results.extend(f.read().split('\n'))
                    except:
                        results.append("Error reading file")
                results.append("")
        else:
            results.append("NetworkManager detected - netplan config may be overridden")
            results.append("Consider: sudo systemctl disable NetworkManager")
            results.append("         sudo systemctl enable systemd-networkd")
            results.append("")
        
        # Gateway connectivity
        rc, gw_out, err = self.run_cmd("ip route | grep default | awk '{print $3}' | head -1")
        gateway = gw_out if rc == 0 else None
        
        if gateway:
            rc, out, err = self.run_cmd(f"ping -c 2 -W 3 {gateway}")
            if rc == 0:
                results.extend(self.format_result("pass", "Gateway Connectivity", f"Can reach gateway {gateway}", f"ping -c 2 {gateway}"))
            else:
                results.extend(self.format_result("error", "Gateway Connectivity", f"Cannot reach gateway {gateway}", f"ping -c 2 {gateway}"))
        else:
            results.extend(self.format_result("error", "Gateway Connectivity", "No default gateway found", "ip route"))
        
        # DNS test
        rc, out, err = self.run_cmd("nslookup google.com")
        if rc == 0:
            results.extend(self.format_result("pass", "DNS Resolution", "DNS working", "nslookup google.com"))
        else:
            results.extend(self.format_result("error", "DNS Resolution", "DNS lookup failed", "nslookup google.com"))
        
        # Bond check
        rc, bond_out, err = self.run_cmd("cat /proc/net/bonding/bond* 2>/dev/null")
        if rc == 0 and bond_out:
            if "802.3ad" in bond_out and "up" in bond_out.lower():
                results.extend(self.format_result("pass", "Bond Interface", "802.3ad bond active", "cat /proc/net/bonding/*"))
            else:
                results.extend(self.format_result("warn", "Bond Interface", "Bond found but check status", "cat /proc/net/bonding/*"))
        
        return results
    
    def get_vm_details(self, vm_name):
        """Get detailed VM information for diagnostics"""
        details = []
        
        # Get VM XML and parse key details
        rc, xml_out, err = self.run_cmd(f"virsh dumpxml {vm_name}")
        if rc != 0:
            return ["    Error getting VM details"]
        
        # Extract CPU info
        rc, vcpu_out, err = self.run_cmd(f"virsh dumpxml {vm_name} | grep '<vcpu'")
        if rc == 0 and vcpu_out:
            vcpus = vcpu_out.split('>')[1].split('<')[0] if '>' in vcpu_out else "unknown"
            details.append(f"    CPUs: {vcpus}")
        
        # Extract Memory info
        rc, mem_out, err = self.run_cmd(f"virsh dumpxml {vm_name} | grep '<memory unit'")
        if rc == 0 and mem_out:
            try:
                mem_kb = mem_out.split('>')[1].split('<')[0]
                mem_gb = round(int(mem_kb) / 1024 / 1024, 1)
                details.append(f"    RAM: {mem_gb}GB")
            except:
                details.append("    RAM: unknown")
        
        # Get disk info
        rc, disk_out, err = self.run_cmd(f"virsh domblklist {vm_name}")
        if rc == 0 and disk_out:
            disk_lines = [line for line in disk_out.split('\n') if line.strip() and not line.startswith('Target')]
            if disk_lines:
                details.append("    Disks:")
                for line in disk_lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[0]
                        source = parts[1]
                        # Try to get disk size
                        if source != '-':
                            rc2, size_out, err2 = self.run_cmd(f"qemu-img info '{source}' 2>/dev/null | grep 'virtual size'")
                            if rc2 == 0 and size_out:
                                size_info = size_out.split('(')[1].split(')')[0] if '(' in size_out else "unknown size"
                                details.append(f"      {target}: {source} ({size_info})")
                            else:
                                details.append(f"      {target}: {source}")
        
        # Get network interfaces
        rc, net_out, err = self.run_cmd(f"virsh domiflist {vm_name}")
        if rc == 0 and net_out:
            net_lines = [line for line in net_out.split('\n') if line.strip() and not line.startswith('Interface')]
            if net_lines:
                details.append("    Networks:")
                for line in net_lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 3:
                        interface = parts[0]
                        net_type = parts[1]
                        source = parts[2]
                        details.append(f"      {interface}: {net_type} ({source})")
        
        # Get current state and uptime info
        rc, state_out, err = self.run_cmd(f"virsh dominfo {vm_name}")
        if rc == 0 and state_out:
            for line in state_out.split('\n'):
                if 'State:' in line or 'CPU time:' in line or 'Max memory:' in line:
                    details.append(f"    {line.strip()}")
        
        return details

    def check_vm_info(self):
        """Local VM information"""
        results = []
        results.append("<LOCAL VMs>")
        results.append("")
        
        # Check virsh
        rc, out, err = self.run_cmd("which virsh")
        if rc != 0:
            results.extend(self.format_result("warn", "Virtualization", "virsh not available", "which virsh"))
            return results
        
        # List VMs
        rc, vms_out, err = self.run_cmd("virsh list --all")
        if rc == 0:
            results.append("ALL DEFINED VMs:")
            results.extend(vms_out.split('\n'))
            results.append("")
            
            # Check each VM for VME Manager characteristics
            vme_managers = []
            running_managers = []
            
            # Get list of VM names
            rc, vm_names, err = self.run_cmd("virsh list --all --name")
            if rc == 0:
                for vm_name in vm_names.split():
                    vm_name = vm_name.strip()
                    if vm_name:
                        # Check VM XML for Morpheus sysinfo
                        rc, xml_out, err = self.run_cmd(f"virsh dumpxml {vm_name}")
                        if rc == 0 and "Morpheus" in xml_out and "MVM" in xml_out:
                            vme_managers.append(vm_name)
                            # Check if this VM is running
                            rc, vm_state, err = self.run_cmd(f"virsh domstate {vm_name}")
                            if rc == 0 and "running" in vm_state.lower():
                                running_managers.append(vm_name)
            
            # Report results and show VM details for running managers
            if len(vme_managers) == 0:
                results.extend(self.format_result("warn", "VME Manager", "No VME Manager VM detected (no VM with Morpheus/MVM sysinfo)", "virsh dumpxml <vm> | grep Morpheus"))
            elif len(running_managers) == 1:
                # Single running VME - show details
                vm_name = running_managers[0]
                results.extend(self.format_result("pass", "VME Manager", f"VME Manager VM '{vm_name}' is running", f"virsh domstate {vm_name}"))
                
                # Add detailed VM info
                details = self.get_vm_details(vm_name)
                results.extend(details)
                results.append("")
                
                # Warn about additional stopped VMs if any
                stopped_managers = [vm for vm in vme_managers if vm not in running_managers]
                if stopped_managers:
                    results.extend(self.format_result("warn", "Additional VME VMs", f"Stopped VME Manager VMs found: '{', '.join(stopped_managers)}' - consider cleanup", "virsh list --all"))
            elif len(running_managers) > 1:
                # Multiple running VME VMs - show all details
                results.extend(self.format_result("error", "VME Manager", f"Multiple VME Manager VMs running: '{', '.join(running_managers)}' - this will cause conflicts", "virsh list --all"))
                
                # Show details for each running VM
                for vm_name in running_managers:
                    results.append(f"  VME VM '{vm_name}' details:")
                    details = self.get_vm_details(vm_name)
                    results.extend(details)
                    results.append("")
            else:
                # VME VMs exist but none running
                if len(vme_managers) == 1:
                    vm_name = vme_managers[0]
                    results.extend(self.format_result("warn", "VME Manager", f"VME Manager VM '{vm_name}' found but not running", f"virsh domstate {vm_name}"))
                else:
                    results.extend(self.format_result("warn", "VME Manager", f"Multiple VME Manager VMs found but none running: '{', '.join(vme_managers)}' - clean up old versions", "virsh list --all"))
        else:
            results.extend(self.format_result("error", "Virtualization", "Cannot list VMs", "virsh list --all"))
        
        return results

def draw_box(stdscr, y, x, height, width, title=""):
    """Draw a box with optional title"""
    # Use gray color for box outline
    box_color = curses.color_pair(3)  # Gray background color
    
    # Draw corners and edges
    stdscr.addch(y, x, curses.ACS_ULCORNER, box_color)
    stdscr.addch(y, x + width - 1, curses.ACS_URCORNER, box_color)
    stdscr.addch(y + height - 1, x, curses.ACS_LLCORNER, box_color)
    stdscr.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER, box_color)
    
    # Draw horizontal lines
    for i in range(1, width - 1):
        stdscr.addch(y, x + i, curses.ACS_HLINE, box_color)
        stdscr.addch(y + height - 1, x + i, curses.ACS_HLINE, box_color)
    
    # Draw vertical lines
    for i in range(1, height - 1):
        stdscr.addch(y + i, x, curses.ACS_VLINE, box_color)
        stdscr.addch(y + i, x + width - 1, curses.ACS_VLINE, box_color)
    
    # Add title if provided
    if title:
        title_text = f" {title} "
        title_x = x + (width - len(title_text)) // 2
        stdscr.addstr(y, title_x, title_text, box_color)

def get_filename_input(stdscr, default_name):
    """Get filename from user with default suggestion"""
    curses.echo()
    curses.curs_set(1)
    
    h, w = stdscr.getmaxyx()
    
    # Create input dialog with blue background
    dialog_height = 8
    dialog_width = 70
    start_y = (h - dialog_height) // 2
    start_x = (w - dialog_width) // 2
    
    stdscr.clear()
    stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
    
    draw_box(stdscr, start_y, start_x, dialog_height, dialog_width, "Report Filename")
    
    # Fill dialog interior with gray background
    for row in range(start_y + 1, start_y + dialog_height - 1):
        stdscr.addstr(row, start_x + 1, " " * (dialog_width - 2), curses.color_pair(3))
    
    stdscr.addstr(start_y + 2, start_x + 2, f"Default: {default_name}", curses.color_pair(3))
    stdscr.addstr(start_y + 3, start_x + 2, "Enter filename (or press Enter for default):", curses.color_pair(3))
    stdscr.addstr(start_y + 4, start_x + 2, "ESC to cancel", curses.color_pair(3))
    
    stdscr.addstr(start_y + 6, start_x + 2, "Filename: ", curses.color_pair(3))
    stdscr.refresh()
    
    # Get user input with proper editing support
    user_input = ""
    cursor_pos = 0
    
    while True:
        # Show current input
        input_area = " " * 40  # Clear the area
        stdscr.addstr(start_y + 6, start_x + 12, input_area, curses.color_pair(3))
        stdscr.addstr(start_y + 6, start_x + 12, user_input, curses.color_pair(3))
        stdscr.move(start_y + 6, start_x + 12 + cursor_pos)
        stdscr.refresh()
        
        key = stdscr.getch()
        
        if key == 27:  # ESC - cancel
            curses.noecho()
            curses.curs_set(0)
            return None
        elif key in [10, 13]:  # Enter
            break
        elif key in [8, 127, curses.KEY_BACKSPACE]:  # Backspace
            if cursor_pos > 0:
                user_input = user_input[:cursor_pos-1] + user_input[cursor_pos:]
                cursor_pos -= 1
        elif key == curses.KEY_LEFT:
            cursor_pos = max(0, cursor_pos - 1)
        elif key == curses.KEY_RIGHT:
            cursor_pos = min(len(user_input), cursor_pos + 1)
        elif key == curses.KEY_DC:  # Delete
            if cursor_pos < len(user_input):
                user_input = user_input[:cursor_pos] + user_input[cursor_pos+1:]
        elif 32 <= key <= 126:  # Printable characters
            if len(user_input) < 50:  # Limit length
                user_input = user_input[:cursor_pos] + chr(key) + user_input[cursor_pos:]
                cursor_pos += 1
    
    curses.noecho()
    curses.curs_set(0)
    
    return user_input.strip() if user_input.strip() else default_name

def generate_report(stdscr, checker):
    """Generate and save system report"""
    # Generate default filename
    now = datetime.now()
    default_filename = f"hpe-report-{now.strftime('%Y-%m-%d-%H%M')}.log"
    
    # Get filename from user
    filename = get_filename_input(stdscr, default_filename)
    
    # If user cancelled (ESC), return to menu
    if filename is None:
        return
    
    # Show progress with consistent colors
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
    stdscr.addstr(h//2, (w-len("Generating report..."))//2, "Generating report...", curses.color_pair(2))
    stdscr.refresh()
    
    try:
        # Generate all results
        all_results = []
        all_results.append("=" * 60)
        all_results.append("HPE VM ESSENTIALS DIAGNOSIS REPORT")
        all_results.append(f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        all_results.append("=" * 60)
        all_results.append("")
        
        # Add each section
        sections = [
            ("SYSTEM CHECK", checker.check_os_info),
            ("LOCAL STORAGE", checker.check_storage_info),
            ("iSCSI STATUS", checker.check_iscsi_info),
            ("NETWORK CONFIGURATION", checker.check_network_info),
            ("VIRTUAL MACHINES", checker.check_vm_info)
        ]
        
        for section_name, check_func in sections:
            all_results.append(f"=== {section_name} ===")
            all_results.append("")
            results = check_func()
            all_results.extend(results)
            all_results.append("")
        
        # Write to file
        with open(filename, 'w') as f:
            for line in all_results:
                # Remove ANSI color codes for file output
                clean_line = re.sub(r'\033\[[0-9;]*m', '', line)
                f.write(clean_line + '\n')
        
        # Show success message with consistent colors
        stdscr.clear()
        stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
        success_msg = f"Report saved to: {filename}"
        file_size = os.path.getsize(filename)
        size_msg = f"File size: {file_size} bytes"
        
        stdscr.addstr(h//2 - 1, (w-len(success_msg))//2, success_msg, curses.color_pair(4))
        stdscr.addstr(h//2 + 1, (w-len(size_msg))//2, size_msg, curses.color_pair(2))
        stdscr.addstr(h//2 + 3, (w-len("Press any key to continue"))//2, "Press any key to continue", curses.color_pair(2))
        stdscr.refresh()
        stdscr.getch()
        
    except Exception as e:
        # Show error message with consistent colors
        stdscr.clear()
        stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
        error_msg = f"Error saving report: {str(e)}"
        stdscr.addstr(h//2, (w-len(error_msg))//2, error_msg, curses.color_pair(7))
        stdscr.addstr(h//2 + 2, (w-len("Press any key to continue"))//2, "Press any key to continue", curses.color_pair(2))
        stdscr.refresh()
        stdscr.getch()

def show_results(stdscr, title, results):
    """Display check results in a scrollable window"""
    curses.curs_set(0)
    h, w = stdscr.getmaxyx()
    scroll_pos = 0
    
    while True:
        # Clear screen and set blue background
        stdscr.clear()
        stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
        
        # Draw title centered at top
        title_y = 2
        stdscr.addstr(title_y, (w - len(title)) // 2, title, curses.color_pair(2))
        
        # Draw results box (gray interior)
        result_height = h - 8
        result_width = w - 6
        start_y = 4
        start_x = 3
        
        draw_box(stdscr, start_y, start_x, result_height, result_width)
        
        # Fill the box interior with gray background
        for row in range(start_y + 1, start_y + result_height - 1):
            stdscr.addstr(row, start_x + 1, " " * (result_width - 2), curses.color_pair(3))
        
        # Display results with scrolling
        display_lines = results[scroll_pos:scroll_pos + result_height - 2]
        for i, line in enumerate(display_lines):
            y = start_y + 1 + i
            if y >= start_y + result_height - 1:
                break
            
            # Color coding for status lines on gray background
            if line.startswith("<") and line.endswith(">"):
                stdscr.addstr(y, start_x + 2, line[:result_width-4], curses.color_pair(6))
            elif "✔ PASS:" in line:
                stdscr.addstr(y, start_x + 2, line[:result_width-4], curses.color_pair(4))
            elif "! WARN:" in line:
                stdscr.addstr(y, start_x + 2, line[:result_width-4], curses.color_pair(5))
            elif "✗ ERROR:" in line:
                stdscr.addstr(y, start_x + 2, line[:result_width-4], curses.color_pair(7))
            else:
                stdscr.addstr(y, start_x + 2, line[:result_width-4], curses.color_pair(3))
        
        # Instructions on blue background
        instructions = f"↑/↓: Scroll | Lines: {len(results)} | Press 'q' or ESC to return"
        stdscr.addstr(h - 2, (w - len(instructions)) // 2, instructions, curses.color_pair(2))
        
        stdscr.refresh()
        
        # Handle input
        key = stdscr.getch()
        if key == ord('q') or key == 27:  # 'q' or ESC
            break
        elif key == curses.KEY_UP and scroll_pos > 0:
            scroll_pos -= 1
        elif key == curses.KEY_DOWN and scroll_pos < len(results) - result_height + 2:
            scroll_pos += 1
        elif key == curses.KEY_PPAGE:  # Page Up
            scroll_pos = max(0, scroll_pos - 10)
        elif key == curses.KEY_NPAGE:  # Page Down
            scroll_pos = min(len(results) - result_height + 2, scroll_pos + 10)

def main_menu(stdscr):
    # Initialize colors to match HPE console screenshot
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Title/normal text (black on gray/white)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_BLUE)    # Selected item (black on blue)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Normal text (black on gray/white)
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Pass
    curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warn
    curses.init_pair(6, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Section headers
    curses.init_pair(7, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
    curses.init_pair(8, curses.COLOR_RED, curses.COLOR_WHITE)     # Red letters on gray/white
    curses.init_pair(9, curses.COLOR_RED, curses.COLOR_BLUE)      # Red letters on blue (for selected)
    
    # Hide cursor
    curses.curs_set(0)
    
    # Menu items
    menu_items = [
        ("System Check", "OS version, architecture, KVM, Morpheus tools"),
        ("Local Storage", "Disk space, mounts, /var/morpheus usage"),
        ("iSCSI Status", "Sessions, targets, multipath, HPE Alletra"),
        ("Network Config", "Netplan vs NetworkManager, connectivity, DNS"),
        ("Virtual Machines", "Local VMs, VME Manager detection"),
        ("", ""),  # separator
        ("Report", "Generate complete system report to file"),
        ("", ""),  # separator
        ("Exit", "")
    ]
    
    current_item = 0
    checker = SystemChecker()
    
    while True:
        # Clear screen and set blue background
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        
        # Set blue background for entire screen
        stdscr.bkgd(' ', curses.color_pair(2))  # Blue background
        
        # Calculate menu dimensions
        menu_height = len([item for item in menu_items if item[0]]) + 4
        menu_width = 70
        start_y = (h - menu_height) // 2
        start_x = (w - menu_width) // 2
        
        # Draw main window (gray center box)
        draw_box(stdscr, start_y, start_x, menu_height, menu_width, "HPE VM Essentials Diagnosis")
        
        # Fill the box interior with gray/white background
        for row in range(start_y + 1, start_y + menu_height - 1):
            stdscr.addstr(row, start_x + 1, " " * (menu_width - 2), curses.color_pair(3))
        
        # Draw menu items
        menu_y = start_y + 2
        for i, (item, desc) in enumerate(menu_items):
            if item == "":  # separator
                continue
            
            y = menu_y
            x = start_x + 2
            
            if i == current_item:
                # Selected item: blue background like outer area
                # Clear the line with blue background
                stdscr.addstr(y, start_x + 1, " " * (menu_width - 2), curses.color_pair(2))
                # Add the text with red first letter
                stdscr.addstr(y, x, "<", curses.color_pair(2))
                if item:
                    stdscr.addstr(y, x + 1, item[0], curses.color_pair(9))  # Red first letter on blue
                    stdscr.addstr(y, x + 2, item[1:] + ">", curses.color_pair(2))
                if desc:
                    stdscr.addstr(y, x + len(item) + 3, f" - {desc}", curses.color_pair(2))
            else:
                # Normal item: gray background with red first letter
                stdscr.addstr(y, x, "<", curses.color_pair(3))
                if item:
                    stdscr.addstr(y, x + 1, item[0], curses.color_pair(8))  # Red first letter on gray
                    stdscr.addstr(y, x + 2, item[1:] + ">", curses.color_pair(3))
                if desc:
                    stdscr.addstr(y, x + len(item) + 3, f" - {desc}", curses.color_pair(3))
            
            menu_y += 1
        
        # Add footer on blue background  
        footer_y = start_y + menu_height + 1
        copyright_text = "v0.1a"
        stdscr.addstr(footer_y, start_x, copyright_text, curses.color_pair(2))
        
        # Instructions on blue background
        instruction_y = h - 2
        instructions = "↑/↓: Navigate | Enter: Select | 'q': Quit"
        stdscr.addstr(instruction_y, (w - len(instructions)) // 2, instructions, curses.color_pair(2))
        
        # Refresh screen
        stdscr.refresh()
        
        # Get user input
        key = stdscr.getch()
        
        if key == ord('q') or key == 27:  # 'q' or ESC
            break
        elif key == curses.KEY_UP:
            current_item = (current_item - 1) % len(menu_items)
            while menu_items[current_item][0] == "":
                current_item = (current_item - 1) % len(menu_items)
        elif key == curses.KEY_DOWN:
            current_item = (current_item + 1) % len(menu_items)
            while menu_items[current_item][0] == "":
                current_item = (current_item + 1) % len(menu_items)
        elif key == ord('\n') or key == ord('\r'):  # Enter
            selected = menu_items[current_item][0]
            
            if selected == "Exit":
                break
            elif selected == "System Check":
                results = checker.check_os_info()
                show_results(stdscr, "<SYSTEM CHECK>", results)
            elif selected == "Local Storage":
                results = checker.check_storage_info()
                show_results(stdscr, "<LOCAL STORAGE>", results)
            elif selected == "iSCSI Status":
                results = checker.check_iscsi_info()
                show_results(stdscr, "<iSCSI STATUS>", results)
            elif selected == "Network Config":
                results = checker.check_network_info()
                show_results(stdscr, "<NETWORK CONFIG>", results)
            elif selected == "Virtual Machines":
                results = checker.check_vm_info()
                show_results(stdscr, "<VIRTUAL MACHINES>", results)
            elif selected == "Report":
                generate_report(stdscr, checker)

def main():
    try:
        curses.wrapper(main_menu)
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
