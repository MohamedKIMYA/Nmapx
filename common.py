import json
import os
import re
import tempfile
from datetime import datetime
from typing import Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

try:
    import nmap as nmap_lib
    HAS_NMAP_LIB = True
except ImportError:
    nmap_lib = None
    HAS_NMAP_LIB = False

try:
    from tqdm.asyncio import tqdm as async_tqdm
    import tqdm as tqdm_mod
    HAS_TQDM = True
except ImportError:
    async_tqdm = None
    tqdm_mod = None
    HAS_TQDM = False

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ██╗  ██╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ╚██╗██╔╝
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝     ╚███╔╝
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝      ██╔██╗
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ██╔╝ ██╗
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝
{C.RESET}{C.DIM}  v3.0 — Async CVE | XML Parser | Diff | Progress | CIDR Exclusion{C.RESET}
{C.YELLOW}  ════════════════════════════════════════════════════════════{C.RESET}
"""

SCAN_PROFILES = {
    "quick":      {"desc": "Top 100 ports, T4",                    "flags": ["-T4", "--top-ports", "100"]},
    "full":       {"desc": "All 65535 ports",                      "flags": ["-T4", "-p-"]},
    "stealth":    {"desc": "SYN stealth scan (root required)",      "flags": ["-sS", "-T2", "-p-"]},
    "service":    {"desc": "Service & version detection",           "flags": ["-sV", "--version-intensity", "7", "-T4"]},
    "os":         {"desc": "OS fingerprinting (root required)",     "flags": ["-O", "-T4"]},
    "vuln":       {"desc": "NSE vuln scripts",                      "flags": ["-sV", "--script=vuln", "-T4"]},
    "aggressive": {"desc": "OS + version + scripts + traceroute",  "flags": ["-A", "-T4"]},
    "udp":        {"desc": "UDP top 100 (root required)",           "flags": ["-sU", "-T4", "--top-ports", "100"]},
    "ping":       {"desc": "Host discovery only",                   "flags": ["-sn"]},
    "custom":     {"desc": "Use --flags for raw nmap flags",        "flags": []},
}

PORT_COLORS = {"open": C.GREEN, "closed": C.RED, "filtered": C.YELLOW}

DB_PATH = os.path.expanduser("~/.nmapx_sessions.db")
NMAP_BIN = "nmap"
COMMON_NMAP_PATHS = [
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
]


def safe_path_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def scan_identity(profile: str, ports_arg: str, extra_flags: list, script_args: str, excludes: str, proxies: str) -> str:
    return json.dumps({
        "profile": profile,
        "ports": ports_arg or "",
        "extra_flags": extra_flags or [],
        "script_args": script_args or "",
        "exclude": excludes or "",
        "proxies": proxies or "",
    }, sort_keys=True)


def port_key(port: dict) -> str:
    return f"{port.get('host', 'unknown')}:{port['port']}/{port['proto']}"


def build_scan_events(target: str, current_ports: list[dict], previous_ports: list[dict]) -> list[dict]:
    events = []
    old_map = {port_key(p): p for p in previous_ports if "open" in p.get("state", "")}
    new_map = {port_key(p): p for p in current_ports if "open" in p.get("state", "")}

    if previous_ports:
        for key, port in new_map.items():
            if key not in old_map:
                events.append({"type": "new-port", "target": target, "port": port})
        for key, port in new_map.items():
            old = old_map.get(key)
            if old and old.get("version", "") != port.get("version", ""):
                events.append({"type": "version-change", "target": target, "old": old, "port": port})

    for port in current_ports:
        for cve in port.get("cves", []):
            severity = str(cve.get("severity", "")).upper()
            if severity in {"CRITICAL", "HIGH"}:
                events.append({"type": "critical-cve", "target": target, "port": port, "cve": cve})

    return events


def extract_os_hint(raw_output: str) -> str:
    for line in raw_output.splitlines():
        if "OS details:" in line:
            return line.split("OS details:", 1)[1].strip()
        if "Aggressive OS guesses:" in line:
            return line.split("Aggressive OS guesses:", 1)[1].strip()
    return ""
