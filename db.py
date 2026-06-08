import hashlib
import json
import sqlite3
import threading
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from common import DB_PATH, C

class SessionDB:
    def __init__(self, path: str = DB_PATH):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30, isolation_level=None)
        self._init()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _init(self):
        self.conn.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS sessions (
                id        TEXT PRIMARY KEY,
                target    TEXT,
                profile   TEXT,
                flags     TEXT,
                status    TEXT DEFAULT 'pending',
                started   TEXT,
                finished  TEXT,
                raw       TEXT
            );
            CREATE TABLE IF NOT EXISTS ports (
                session_id TEXT,
                host       TEXT,
                port       TEXT,
                proto      TEXT,
                state      TEXT,
                service    TEXT,
                version    TEXT,
                cpe        TEXT,
                cves       TEXT
            );
        """)
        self.conn.commit()
        # _init runs from __init__ before any async access — no lock needed here
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(ports)").fetchall()}
        if "host" not in columns:
            self.conn.execute("ALTER TABLE ports ADD COLUMN host TEXT DEFAULT 'unknown'")
        if "cpe" not in columns:
            self.conn.execute("ALTER TABLE ports ADD COLUMN cpe TEXT DEFAULT ''")
        if "cves" not in columns:
            self.conn.execute("ALTER TABLE ports ADD COLUMN cves TEXT DEFAULT '[]'")
        self.conn.commit()

    def session_id(self, target: str, profile: str, flags: str) -> str:
        seed = datetime.now().isoformat(timespec="microseconds")
        return hashlib.md5(f"{target}|{profile}|{flags}|{seed}".encode()).hexdigest()[:12]

    def get(self, sid: str) -> Optional[Dict]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row:
            return None
        return dict(zip(["id","target","profile","flags","status","started","finished","raw"], row))

    def create(self, sid: str, target: str, profile: str, flags: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions(id,target,profile,flags,status,started) VALUES(?,?,?,?,?,?)",
                (sid, target, profile, flags, "running", datetime.now().isoformat())
            )
            self.conn.commit()

    def finish(self, sid: str, raw: str):
        with self.lock:
            self.conn.execute(
                "UPDATE sessions SET status='done', finished=?, raw=? WHERE id=?",
                (datetime.now().isoformat(), raw, sid)
            )
            self.conn.commit()

    def fail(self, sid: str, raw: str = ""):
        with self.lock:
            self.conn.execute(
                "UPDATE sessions SET status='error', finished=?, raw=? WHERE id=?",
                (datetime.now().isoformat(), raw, sid)
            )
            self.conn.commit()

    def save_ports(self, sid: str, ports: List[Dict]):
        with self.lock:
            self.conn.execute("DELETE FROM ports WHERE session_id=?", (sid,))
            for p in ports:
                self.conn.execute(
                    "INSERT INTO ports VALUES(?,?,?,?,?,?,?,?,?)",
                    (sid, p.get("host", "unknown"), p["port"], p["proto"], p["state"],
                     p["service"], p["version"], p.get("cpe", ""), json.dumps(p.get("cves", [])))
                )
            self.conn.commit()

    def load_ports(self, sid: str) -> List[Dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT host,port,proto,state,service,version,cpe,cves FROM ports WHERE session_id=?", (sid,)
            ).fetchall()
        return [{
            "host": r[0], "port": r[1], "proto": r[2], "state": r[3],
            "service": r[4], "version": r[5], "cpe": r[6],
            "cves": json.loads(r[7]) if r[7] else []
        } for r in rows]

    def list_sessions(self) -> List[Dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id,target,profile,status,started,finished FROM sessions ORDER BY started DESC LIMIT 20"
            ).fetchall()
        return [dict(zip(["id","target","profile","status","started","finished"], r)) for r in rows]

    def find_completed(self, target: str, profile: str, flags: str) -> Optional[Dict]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE target=? AND profile=? AND flags=? AND status='done' "
                "ORDER BY finished DESC LIMIT 1",
                (target, profile, flags)
            ).fetchone()
        if not row:
            return None
        return dict(zip(["id","target","profile","flags","status","started","finished","raw"], row))

    def get_latest_completed(self, target: str) -> Optional[Dict]:
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM sessions WHERE target=? AND status='done' ORDER BY finished DESC LIMIT 1",
                (target,)
            ).fetchone()
        if not row:
            return None
        meta = self.get(row[0])
        return {"meta": meta, "ports": self.load_ports(row[0])}

    def get_last_two_sessions(self, target: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id FROM sessions WHERE target=? AND status='done' ORDER BY finished DESC LIMIT 2",
                (target,)
            ).fetchall()
        sessions = []
        for row in rows:
            sid = row[0]
            ports = self.load_ports(sid)
            meta = self.get(sid)
            sessions.append({"meta": meta, "ports": ports})
        if len(sessions) == 2:
            return sessions[0], sessions[1]
        return None, None

    def close(self):
        self.conn.close()


def diff_sessions(target: str, db: SessionDB):
    newest, older = db.get_last_two_sessions(target)
    if not newest or not older:
        print(f"\n{C.YELLOW}[!] Need at least 2 completed scans for '{target}' to diff.{C.RESET}\n")
        return

    def port_key(p):
        return f"{p.get('host','unknown')}:{p['port']}/{p['proto']}"

    def cve_ids(port):
        return {c.get('id') for c in port.get('cves', []) if c.get('id')}

    old_map = {port_key(p): p for p in older["ports"]}
    new_map = {port_key(p): p for p in newest["ports"]}

    opened = [p for k, p in new_map.items() if k not in old_map]
    closed = [p for k, p in old_map.items() if k not in new_map]
    version_changed = [
        (old_map[k], new_map[k])
        for k in old_map
        if k in new_map and old_map[k]["version"] != new_map[k]["version"]
    ]
    service_changed = [
        (old_map[k], new_map[k])
        for k in old_map
        if k in new_map and old_map[k].get("service") != new_map[k].get("service")
    ]
    cpe_changed = [
        (old_map[k], new_map[k])
        for k in old_map
        if k in new_map and old_map[k].get("cpe") != new_map[k].get("cpe")
    ]

    cve_added = []
    cve_removed = []
    for k in old_map:
        if k in new_map:
            old_ids = cve_ids(old_map[k])
            new_ids = cve_ids(new_map[k])
            added = sorted(new_ids - old_ids)
            removed = sorted(old_ids - new_ids)
            if added:
                cve_added.append((new_map[k], added))
            if removed:
                cve_removed.append((new_map[k], removed))

    t_old = older["meta"]["finished"][:19]
    t_new = newest["meta"]["finished"][:19]

    print(f"\n{C.CYAN}{'═'*60}{C.RESET}")
    print(f"  {C.BOLD}DIFF — {target}{C.RESET}")
    print(f"  Older : {C.DIM}{t_old}{C.RESET}")
    print(f"  Newer : {C.DIM}{t_new}{C.RESET}")
    print(f"{C.CYAN}{'═'*60}{C.RESET}\n")

    if opened:
        print(f"  {C.GREEN}{C.BOLD}[+] Newly OPEN ports ({len(opened)}):{C.RESET}")
        for p in opened:
            print(f"      {C.GREEN}{p.get('host', 'unknown')} - {p['port']}/{p['proto']:<6}{C.RESET} {p['service']} {C.DIM}{p['version']}{C.RESET}")

    if closed:
        print(f"\n  {C.RED}{C.BOLD}[-] Newly CLOSED ports ({len(closed)}):{C.RESET}")
        for p in closed:
            print(f"      {C.RED}{p.get('host', 'unknown')} - {p['port']}/{p['proto']:<6}{C.RESET} {p['service']} {C.DIM}{p['version']}{C.RESET}")

    if version_changed:
        print(f"\n  {C.YELLOW}{C.BOLD}[~] Version CHANGED ({len(version_changed)}):{C.RESET}")
        for old_p, new_p in version_changed:
            print(f"      {C.YELLOW}{old_p.get('host', 'unknown')} - {old_p['port']}/{old_p['proto']}{C.RESET}")
            print(f"        Before: {C.DIM}{old_p['version'] or '?'}{C.RESET}")
            print(f"        After : {C.WHITE}{new_p['version'] or '?'}{C.RESET}")

    if service_changed:
        print(f"\n  {C.CYAN}{C.BOLD}[~] Service CHANGED ({len(service_changed)}):{C.RESET}")
        for old_p, new_p in service_changed:
            if old_p['service'] != new_p['service']:
                print(f"      {C.CYAN}{old_p.get('host', 'unknown')} - {old_p['port']}/{old_p['proto']}{C.RESET}")
                print(f"        Before: {C.DIM}{old_p['service'] or '?'}{C.RESET}")
                print(f"        After : {C.WHITE}{new_p['service'] or '?'}{C.RESET}")

    if cpe_changed:
        print(f"\n  {C.MAGENTA}{C.BOLD}[~] CPE CHANGED ({len(cpe_changed)}):{C.RESET}")
        for old_p, new_p in cpe_changed:
            print(f"      {C.MAGENTA}{old_p.get('host', 'unknown')} - {old_p['port']}/{old_p['proto']}{C.RESET}")
            print(f"        Before: {C.DIM}{old_p.get('cpe') or '?'}{C.RESET}")
            print(f"        After : {C.WHITE}{new_p.get('cpe') or '?'}{C.RESET}")

    if cve_added:
        print(f"\n  {C.GREEN}{C.BOLD}[+] CVEs ADDED ({len(cve_added)}):{C.RESET}")
        for p, added in cve_added:
            print(f"      {C.GREEN}{p.get('host', 'unknown')} - {p['port']}/{p['proto']}{C.RESET} {', '.join(added)}")

    if cve_removed:
        print(f"\n  {C.RED}{C.BOLD}[-] CVEs REMOVED ({len(cve_removed)}):{C.RESET}")
        for p, removed in cve_removed:
            print(f"      {C.RED}{p.get('host', 'unknown')} - {p['port']}/{p['proto']}{C.RESET} {', '.join(removed)}")

    if not (opened or closed or version_changed or service_changed or cpe_changed or cve_added or cve_removed):
        print(f"  {C.GREEN}No changes detected between the two scans.{C.RESET}")

    print(f"\n{C.CYAN}{'═'*60}{C.RESET}\n")
