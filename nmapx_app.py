#!/usr/bin/env python3
import argparse
import asyncio
import os
import shutil
import sys

# Fix encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import common
from db import SessionDB, diff_sessions
from report import export_csv, export_excel, export_json, export_html, print_profiles, print_sessions, print_report, send_telegram_notifications
from scanner import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nmapx",
        description="NmapX v3.0 — Advanced Nmap Python Wrapper by KIMYA_Lab",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IPs, hostnames, or CIDR ranges")
    p.add_argument("-p", "--profile", choices=list(common.SCAN_PROFILES.keys()),
                   default="quick", metavar="PROFILE", help="Scan profile (default: quick)")
    p.add_argument("--ports", metavar="PORTS", help='Port range e.g. "80,443" or "1-1024"')
    p.add_argument("--flags", metavar="FLAGS", help="Extra raw nmap flags")
    p.add_argument("--output", metavar="PATH", help="Save .txt/.xml to this base path")
    p.add_argument("--html", metavar="PATH", help="Export HTML report")
    p.add_argument("--csv", metavar="PATH", help="Export CSV report")
    p.add_argument("--excel", metavar="PATH", help="Export Excel (.xlsx) report")
    p.add_argument("--json", metavar="PATH", help="Export JSON report")
    p.add_argument("--raw", action="store_true", help="Print raw nmap output")
    p.add_argument("--cve", action="store_true", help="CVE enrichment via NVD API")
    p.add_argument("--nvd-key", metavar="KEY", help="NVD API key (or set NVD_API_KEY env var)")
    p.add_argument("--resume", action="store_true", help="Skip already-scanned targets")
    p.add_argument("--workers", type=int, default=3, metavar="N", help="Concurrent scans (default: 3)")
    p.add_argument("--list", action="store_true", help="List scan profiles")
    p.add_argument("--history", action="store_true", help="Show session history")
    p.add_argument("--diff", metavar="TARGET", help="Diff last 2 scans for TARGET")
    p.add_argument("--exclude", metavar="IPS", help="Comma-separated IPs/CIDRs to exclude")
    p.add_argument("--proxies", metavar="URL", help="Comma-separated list of proxy URLs")
    p.add_argument("--target-file", metavar="FILE", help="File with one target per line")
    p.add_argument("--notify", choices=["telegram"], help="Send scan events to a notifier")
    p.add_argument("--notify-on", default="new-port,critical-cve,scan-failed",
                   help="Comma-separated event types: new-port,version-change,critical-cve,scan-failed")
    p.add_argument("--telegram-token", metavar="TOKEN", help="Telegram bot token (or TELEGRAM_BOT_TOKEN)")
    p.add_argument("--telegram-chat-id", metavar="ID", help="Telegram chat id (or TELEGRAM_CHAT_ID)")
    p.add_argument("--script-args", metavar="ARGS",
                   help='NSE script arguments e.g. "http.useragent=nmapx,ftp.anon=true"')
    return p


def check_nmap():
    found = shutil.which("nmap")
    if found:
        common.NMAP_BIN = found
        return
    for candidate in common.COMMON_NMAP_PATHS:
        if os.path.exists(candidate):
            common.NMAP_BIN = candidate
            return
    print(f"{common.C.RED}[!] nmap not found. Install Nmap to use this tool.{common.C.RESET}")
    sys.exit(1)


def check_root_if_needed(profile: str):
    if profile in {"stealth", "os", "udp"}:
        if hasattr(os, "geteuid"):
            if os.geteuid() != 0:
                print(f"{common.C.YELLOW}[!] Profile '{profile}' usually needs root/sudo.{common.C.RESET}\n")
        else:
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    print(f"{common.C.YELLOW}[!] Profile '{profile}' usually needs Administrator privileges.{common.C.RESET}\n")
            except Exception:
                pass


def main():
    print(common.BANNER)
    parser = build_parser()
    args = parser.parse_args()

    with SessionDB() as db:
        if args.list:
            print_profiles()
            sys.exit(0)

        if args.history:
            print_sessions(db)
            sys.exit(0)

        if args.diff:
            diff_sessions(args.diff, db)
            sys.exit(0)

        targets = list(args.targets)
        if args.target_file:
            try:
                with open(args.target_file, encoding="utf-8") as f:
                    targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except FileNotFoundError:
                print(f"{common.C.RED}[!] File not found: {args.target_file}{common.C.RESET}")
                sys.exit(1)

        if not targets:
            parser.print_help()
            print(f"\n{common.C.YELLOW}[!] No targets.{common.C.RESET}\n")
            sys.exit(1)

        check_nmap()

        if args.cve and not common.HAS_HTTPX:
            print(f"{common.C.RED}[!] CVE enrichment needs httpx. Run: pip install httpx{common.C.RESET}")
            sys.exit(1)

        if args.notify == "telegram":
            telegram_token = args.telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
            telegram_chat_id = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
            if not telegram_token or not telegram_chat_id:
                print(f"{common.C.RED}[!] Telegram needs --telegram-token/--telegram-chat-id or TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID.{common.C.RESET}")
                sys.exit(1)
            if not common.HAS_HTTPX:
                print(f"{common.C.RED}[!] Telegram notifications need httpx. Run: pip install httpx{common.C.RESET}")
                sys.exit(1)

        check_root_if_needed(args.profile)

        excludes = [e.strip() for e in args.exclude.split(",")] if args.exclude else []

        print(f"  {common.C.BOLD}Targets  {common.C.RESET}: {common.C.WHITE}{len(targets)} target(s){common.C.RESET}")
        print(f"  {common.C.BOLD}Profile  {common.C.RESET}: {common.C.MAGENTA}{args.profile}{common.C.RESET}")
        print(f"  {common.C.BOLD}Workers  {common.C.RESET}: {args.workers}")
        print(f"  {common.C.BOLD}CVE      {common.C.RESET}: {'ON' + (' [API Key ✓]' if args.nvd_key or os.environ.get('NVD_API_KEY') else ' [no key — may rate-limit]') if args.cve else 'off'}")
        print(f"  {common.C.BOLD}Resume   {common.C.RESET}: {'ON' if args.resume else 'off'}")
        if excludes:
            print(f"  {common.C.BOLD}Exclude  {common.C.RESET}: {common.C.DIM}{', '.join(excludes)}{common.C.RESET}")
        if args.proxies:
            print(f"  {common.C.BOLD}Proxies  {common.C.RESET}: {common.C.DIM}{args.proxies}{common.C.RESET}")
        if args.script_args:
            print(f"  {common.C.BOLD}NSE Args {common.C.RESET}: {common.C.DIM}{args.script_args}{common.C.RESET}")

        try:
            results = asyncio.run(run_all(targets, args, db))
        except KeyboardInterrupt:
            print(f"\n{common.C.YELLOW}[!] Interrupted.{common.C.RESET}")
            sys.exit(0)

        for result in results:
            print_report(result)
            if args.raw and result.get("raw"):
                print(f"{common.C.DIM}{'─'*65}\nRAW:\n{'─'*65}{common.C.RESET}")
                print(result["raw"])

        total_open = sum(len([p for p in r.get("ports", []) if "open" in p["state"]]) for r in results)
        print(f"{common.C.CYAN}{'═'*65}{common.C.RESET}")
        print(f"  {common.C.BOLD}SUMMARY{common.C.RESET}  : {len(results)} target(s)  |  {common.C.GREEN}{total_open} open port(s){common.C.RESET}")
        print(f"{common.C.CYAN}{'═'*65}{common.C.RESET}\n")

        if args.notify == "telegram":
            events = [event for result in results for event in result.get("events", [])]
            allowed_types = {item.strip() for item in args.notify_on.split(",") if item.strip()}
            asyncio.run(send_telegram_notifications(events, telegram_token, telegram_chat_id, allowed_types))
            sent_count = sum(1 for event in events if event.get("type") in allowed_types)
            print(f"  {common.C.GREEN}[+] Telegram notification events: {sent_count}{common.C.RESET}")

        if args.json:
            export_json(results, args.json)
        if args.csv:
            export_csv(results, args.csv)
        if args.html:
            export_html(results, args.html)
        if args.excel:
            export_excel(results, args.excel)


if __name__ == "__main__":
    main()
