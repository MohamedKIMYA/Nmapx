import asyncio
import json
import os
import re
import shlex
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
import ipaddress

import common
from common import C, PORT_COLORS, SCAN_PROFILES, safe_path_part, scan_identity, extract_os_hint, HAS_NMAP_LIB
from cve import CVEEnricher

try:
    import nmap as nmap_lib
except ImportError:
    nmap_lib = None

PORT_PATTERN = re.compile(
    r"(\d+)/(tcp|udp)\s+(open\S*|closed\S*|filtered\S*)\s+(\S+)?\s*(.*)?$"
)

# Security validation functions
def _validate_port_spec(ports_arg: str) -> bool:
    """Validate port specification format (e.g., '80,443', '1-1024')."""
    if not ports_arg:
        return True
    # Only allow digits, commas, hyphens, colons
    if not re.match(r"^[\d,\-:]+$", ports_arg.strip()):
        return False
    return True


def _validate_target(target: str) -> bool:
    """Validate target is a valid IP, CIDR, or hostname."""
    target = target.strip()
    if not target:
        return False
    # Try to parse as IP or CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    # Try to parse as IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    # Validate hostname: alphanumeric, dots, hyphens only
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", target):
        return True
    return False


def _validate_script_args(script_args: str) -> bool:
    """Validate NSE script arguments are safe."""
    if not script_args:
        return True
    # Allow key=value pairs separated by commas
    # Reject shell metacharacters
    dangerous_chars = {";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">"}
    for char in dangerous_chars:
        if char in script_args:
            return False
    return True


def _validate_exclude_list(excludes: str) -> bool:
    """Validate exclude list contains only valid IPs/CIDRs."""
    if not excludes:
        return True
    for item in excludes.split(","):
        item = item.strip()
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            return False
    return True


def _validate_proxies(proxies: str) -> bool:
    """Validate proxy URLs are well-formed."""
    if not proxies:
        return True
    # Basic URL validation: must start with http:// or socks5://
    for proxy in proxies.split(","):
        proxy = proxy.strip()
        if not (proxy.startswith("http://") or proxy.startswith("https://") or proxy.startswith("socks5://")):
            return False
        # Ensure no shell metacharacters
        if any(c in proxy for c in [";", "|", "&", "$", "`", "(", ")"]):
            return False
    return True


def parse_ports_from_xml(xml_path: str) -> List[Dict]:
    if not HAS_NMAP_LIB or not os.path.exists(xml_path):
        return []

    try:
        nm = nmap_lib.PortScanner()
        nm.analyse_nmap_xml_scan(open(xml_path, encoding="utf-8", errors="replace").read())
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port_num in nm[host][proto]:
                    p = nm[host][proto][port_num]
                    version_parts = [
                        p.get("product", ""),
                        p.get("version", ""),
                        p.get("extrainfo", ""),
                    ]
                    version_str = " ".join(v for v in version_parts if v).strip()
                    cpe = p.get("cpe", "")
                    if isinstance(cpe, list):
                        cpe = ", ".join(cpe)
                    ports.append({
                        "host":    host,
                        "port":    str(port_num),
                        "proto":   proto,
                        "state":   p.get("state", "?"),
                        "service": p.get("name", "?"),
                        "version": version_str,
                        "cpe":     cpe,
                        "cves":    [],
                    })
        return ports
    except Exception:
        return []


def parse_ports_regex(raw_output: str) -> List[Dict]:
    ports = []
    current_host = "unknown"
    for line in raw_output.splitlines():
        if "Nmap scan report for" in line:
            current_host = line.split("for")[-1].strip()
        m = PORT_PATTERN.match(line.strip())
        if m:
            version = ""
            if m.lastindex and m.lastindex >= 5:
                version = (m.group(5) or "").strip()
            ports.append({
                "host":    current_host,
                "port":    m.group(1),
                "proto":   m.group(2),
                "state":   m.group(3).split("/")[0],
                "service": m.group(4) or "?",
                "version": version,
                "cpe":     "",
                "cves":    [],
            })
    return ports


async def stream_nmap(cmd: List[str]) -> tuple[str, str, int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    lines = []
    stderr_parts = []
    print(f"\n{C.DIM}  {'─'*58}{C.RESET}")

    async def read_stdout():
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").rstrip()
            lines.append(line)
            m = PORT_PATTERN.match(line.strip())
            if m:
                state = m.group(3).split("/")[0]
                color = PORT_COLORS.get(state, C.WHITE)
                ts = datetime.now().strftime("%H:%M:%S")
                port = m.group(1)
                proto = m.group(2)
                svc = m.group(4) or "?"
                ver = ""
                if m.lastindex and m.lastindex >= 5:
                    ver = (m.group(5) or "").strip()
                print(
                    f"  {C.DIM}[{ts}]{C.RESET} "
                    f"{C.YELLOW}{port}/{proto:<5}{C.RESET} "
                    f"{color}{state:<10}{C.RESET} "
                    f"{C.CYAN}{svc:<14}{C.RESET} "
                    f"{C.DIM}{ver[:40]}{C.RESET}"
                )
            elif "Nmap scan report for" in line or "Host is up" in line:
                print(f"  {C.GREEN}[+]{C.RESET} {C.WHITE}{line.strip()}{C.RESET}")
            elif line.strip().startswith("|") and ("CVE" in line or "VULNERABLE" in line):
                print(f"  {C.RED}[!]{C.RESET} {C.RED}{line.strip()}{C.RESET}")

    async def read_stderr():
        async for raw_line in proc.stderr:
            stderr_parts.append(raw_line.decode(errors="replace").rstrip())

    await asyncio.gather(read_stdout(), read_stderr())
    await proc.wait()
    print(f"{C.DIM}  {'─'*58}{C.RESET}\n")

    stderr = "\n".join(stderr_parts)

    xml_path = ""
    if "-oX" in cmd:
        idx = cmd.index("-oX")
        if idx + 1 < len(cmd):
            xml_path = cmd[idx + 1]

    return "\n".join(lines), stderr, proc.returncode, xml_path


async def run_single(
    target: str,
    profile: str,
    ports_arg: str,
    extra_flags: list,
    output_file: str,
    enrich_cve: bool,
    nvd_key: str,
    script_args: str,
    excludes: str,
    proxies: str,
    db,
    semaphore: asyncio.Semaphore,
    resume: bool,
    progress: Optional[object],
) -> dict:
    # ────── SECURITY VALIDATION ──────
    if not _validate_target(target):
        print(f"\n{C.RED}[!] Invalid target: {target}{C.RESET}")
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": "",
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": 1, "reason": "Invalid target format"}],
        }

    if ports_arg and not _validate_port_spec(ports_arg):
        print(f"\n{C.RED}[!] Invalid port specification: {ports_arg}{C.RESET}")
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": "",
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": 1, "reason": "Invalid port format"}],
        }

    if script_args and not _validate_script_args(script_args):
        print(f"\n{C.RED}[!] Invalid script arguments: {script_args}{C.RESET}")
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": "",
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": 1, "reason": "Unsafe script arguments"}],
        }

    if excludes and not _validate_exclude_list(excludes):
        print(f"\n{C.RED}[!] Invalid exclude list: {excludes}{C.RESET}")
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": "",
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": 1, "reason": "Invalid exclude IPs"}],
        }

    if proxies and not _validate_proxies(proxies):
        print(f"\n{C.RED}[!] Invalid proxy URLs: {proxies}{C.RESET}")
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": "",
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": 1, "reason": "Invalid proxy format"}],
        }

    # ────── END SECURITY VALIDATION ──────
    
    flags_str = scan_identity(profile, ports_arg, extra_flags, script_args, excludes, proxies)
    sid = db.session_id(target, profile, flags_str)

    if resume:
        existing = db.find_completed(target, profile, flags_str)
        if existing:
            print(f"\n{C.YELLOW}[~] Cached → {target} [{sid}]{C.RESET}")
            if progress:
                progress.update(1)
            return {
                "target": target,
                "profile": profile,
                "sid": existing["id"],
                "ports": db.load_ports(existing["id"]),
                "raw": existing["raw"] or "",
                "duration": 0.0,
                "resumed": True,
                "events": [],
            }

    cmd = [common.NMAP_BIN] + SCAN_PROFILES[profile]["flags"]
    if ports_arg and profile != "ping":
        cmd.extend(["-p", ports_arg])
    if extra_flags:
        cmd.extend(extra_flags)
    if script_args:
        cmd.extend(["--script-args", script_args])
    if excludes:
        cmd.extend(["--exclude", excludes])
    if proxies:
        cmd.extend(["--proxies", proxies])

    if output_file:
        output_path = Path(output_file)
        output_dir = output_path.parent or Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)
        base_path = output_dir / f"{output_path.stem}_{safe_path_part(target)}"
    else:
        base_path = Path(tempfile.gettempdir()) / f"nmapx_{sid}"

    xml_path = str(base_path.with_suffix(".xml"))
    cmd.extend(["-oX", xml_path])
    if output_file:
        cmd.extend(["-oN", str(base_path.with_suffix(".txt"))])
    cmd.append(target)

    print(f"\n{C.CYAN}[*] → {C.WHITE}{target}{C.RESET}  {C.DIM}[{sid}]{C.RESET}")
    print(f"    {C.DIM}$ {' '.join(cmd)}{C.RESET}")

    previous = db.get_latest_completed(target)
    previous_ports = previous["ports"] if previous else []
    db.create(sid, target, profile, flags_str)

    async with semaphore:
        start = datetime.now()
        try:
            raw, stderr, returncode, xml_out = await stream_nmap(cmd)
        except asyncio.CancelledError:
            print(f"\n{C.YELLOW}[!] Cancelled: {target}{C.RESET}")
            db.fail(sid, "Cancelled by user")
            if progress:
                progress.update(1)
            return {}
        duration = (datetime.now() - start).total_seconds()

    if returncode != 0:
        print(f"{C.RED}[!] nmap error on {target} (exit {returncode}){C.RESET}")
        if stderr.strip():
            print(f"  {C.RED}[stderr]{C.RESET} {stderr.strip()}")
        db.fail(sid, raw + ("\n" + stderr if stderr else ""))
        if progress:
            progress.update(1)
        return {
            "target": target,
            "profile": profile,
            "sid": sid,
            "error": True,
            "events": [{"type": "scan-failed", "target": target, "exit_code": returncode}],
        }

    parsed_ports = parse_ports_from_xml(xml_out) if HAS_NMAP_LIB else []
    if not parsed_ports:
        parsed_ports = parse_ports_regex(raw)

    os_hint = extract_os_hint(raw)
    if enrich_cve:
        open_with_ver = [p for p in parsed_ports if "open" in p["state"] and p.get("service")]
        if open_with_ver:
            print(f"\n  {C.MAGENTA}[CVE]{C.RESET} Querying NVD for {len(open_with_ver)} service(s) (async)…")
            parsed_ports = await CVEEnricher.enrich_ports(parsed_ports, nvd_key, os_name=os_hint)
            for p in parsed_ports:
                if p.get("cves"):
                    top = p["cves"][0]
                    sc = CVEEnricher.severity_color(top["severity"])
                    print(
                        f"  {C.DIM}  {p['port']}/{p['service']} → "
                        f"{sc}{top['id']} [{top['score']}]{C.RESET}"
                    )

    events = common.build_scan_events(target, parsed_ports, previous_ports)
    db.finish(sid, raw)
    db.save_ports(sid, parsed_ports)
    if progress:
        progress.update(1)

    return {
        "target": target,
        "profile": profile,
        "sid": sid,
        "cmd": cmd,
        "ports": parsed_ports,
        "raw": raw,
        "os": os_hint,
        "duration": duration,
        "resumed": False,
        "events": events,
    }


async def run_all(targets: List[str], args, db) -> List[dict]:
    semaphore = asyncio.Semaphore(args.workers)
    extra_flags = shlex.split(args.flags) if args.flags else []
    nvd_key = args.nvd_key or os.environ.get("NVD_API_KEY", "")
    script_args = args.script_args or ""

    progress = None
    if common.HAS_TQDM and len(targets) > 1:
        progress = common.tqdm_mod.tqdm(
            total=len(targets),
            desc=f"{C.CYAN}  Scanning{C.RESET}",
            unit="host",
            ncols=70,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        )

    tasks = [
        run_single(
            target=t,
            profile=args.profile,
            ports_arg=args.ports or "",
            extra_flags=extra_flags,
            output_file=args.output,
            enrich_cve=args.cve,
            nvd_key=nvd_key,
            script_args=script_args,
            excludes=args.exclude,
            proxies=args.proxies,
            db=db,
            semaphore=semaphore,
            resume=args.resume,
            progress=progress,
        )
        for t in targets
    ]

    results = await asyncio.gather(*tasks, return_exceptions=False)
    if progress:
        progress.close()
    return [r for r in results if r]
