import asyncio
import re
from typing import List, Optional
from common import HAS_HTTPX, httpx, C


def _sanitize_error_message(message: str, api_key: str = "") -> str:
    """Remove sensitive data from error messages."""
    if not message:
        return message
    msg = str(message)
    if api_key and api_key in msg:
        masked = api_key[:4] + "*" * max(0, len(api_key) - 8) + api_key[-4:] if len(api_key) > 8 else "****"
        msg = msg.replace(api_key, masked)
    msg = re.sub(r"apiKey['\"]?\s*[:\\=]\s*[^'\"\s;,}]+", "apiKey=****", msg, flags=re.IGNORECASE)
    return msg

class CVEEnricher:
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE: dict = {}
    SEVERITY_COLORS = {
        "CRITICAL": C.RED,
        "HIGH": C.YELLOW,
        "MEDIUM": C.BLUE,
        "LOW": C.GREEN,
        "N/A": C.DIM,
    }

    @classmethod
    def severity_color(cls, severity: str) -> str:
        return cls.SEVERITY_COLORS.get(str(severity).upper(), C.WHITE)

    @classmethod
    def _build_query(cls, keyword: str = "", cpe: str = "", os_name: str = "", max_results: int = 5) -> tuple[dict, str, str]:
        params = {"resultsPerPage": max_results}
        query_text = ""
        match_type = "keyword"

        if cpe:
            params["cpeName"] = cpe.strip()
            query_text = cpe.strip()
            match_type = "cpe"
            if keyword:
                params["keywordSearch"] = keyword.strip()
        elif keyword:
            query_text = keyword.strip()
            if os_name:
                params["keywordSearch"] = f"{keyword.strip()} {os_name.strip()}"
            else:
                params["keywordSearch"] = keyword.strip()
        elif os_name:
            query_text = os_name.strip()
            params["keywordSearch"] = os_name.strip()

        return params, query_text, match_type

    @classmethod
    async def query(cls, keyword: str = "", api_key: str = "", cpe: str = "", os_name: str = "", max_results: int = 5) -> List[dict]:
        if not HAS_HTTPX:
            return []
        if not keyword and not cpe and not os_name:
            return []

        cache_key = " | ".join(filter(None, [keyword.strip().lower(), cpe.strip().lower(), os_name.strip().lower(), str(max_results)]))
        if cache_key in cls.CACHE:
            return cls.CACHE[cache_key]

        params, query_text, match_type = cls._build_query(keyword, cpe, os_name, max_results)
        try:
            headers = {"User-Agent": "nmapx/3.0"}
            if api_key:
                headers["apiKey"] = api_key

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(cls.BASE, params=params, headers=headers)
                if resp.status_code == 403:
                    print(f"\n  {C.RED}[CVE] NVD API: 403 Forbidden — provide --nvd-key to avoid rate limits{C.RESET}")
                    return []
                if resp.status_code == 503:
                    print(f"\n  {C.YELLOW}[CVE] NVD API: 503 — rate limited. Use --nvd-key or reduce --workers{C.RESET}")
                    return []
                resp.raise_for_status()
                data = resp.json()
        except httpx.RequestError as exc:
            safe_msg = _sanitize_error_message(str(exc), api_key)
            print(f"\n  {C.RED}[CVE] Request failed (network error) {C.DIM}({safe_msg}){C.RESET}")
            return []
        except httpx.HTTPStatusError as exc:
            safe_msg = _sanitize_error_message(str(exc), api_key)
            if exc.response.status_code >= 500:
                print(f"\n  {C.YELLOW}[CVE] NVD API server error (HTTP {exc.response.status_code}) {C.DIM}({safe_msg}){C.RESET}")
            else:
                print(f"\n  {C.RED}[CVE] Request error (HTTP {exc.response.status_code}) {C.DIM}({safe_msg}){C.RESET}")
            return []
        except Exception as exc:
            safe_msg = _sanitize_error_message(str(exc), api_key)
            print(f"\n  {C.RED}[CVE] Unexpected error {C.DIM}({safe_msg}){C.RESET}")
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = next(
                (d["value"][:140] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            score, severity = "N/A", "N/A"
            metrics = cve.get("metrics", {})
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(ver):
                    score = metrics[ver][0].get("cvssData", {}).get("baseScore", "N/A")
                    severity = metrics[ver][0].get("cvssData", {}).get("baseSeverity", "N/A")
                    break
            cves.append({
                "id": cid,
                "score": score,
                "severity": severity,
                "desc": desc,
                "query": query_text,
                "confidence": cls.compute_confidence(query_text, desc, os_name),
                "match_type": match_type,
            })

        cls.CACHE[cache_key] = cves
        return cves

    @classmethod
    def _mask_api_key_for_logging(cls, api_key: str) -> str:
        """Return a safe representation of API key for logging."""
        if not api_key:
            return "<no-key>"
        if len(api_key) <= 8:
            return "****"
        return api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:]

    @classmethod
    async def enrich_ports(cls, ports: list[dict], api_key: str = "", os_name: str = "", max_concurrent: int = 3) -> list[dict]:
        """Enrich open ports with CVE data from NVD API.

        Uses a semaphore to limit concurrent requests to NVD, preventing
        rate-limiting (429/503) responses. Even with an API key, NVD is strict
        about burst traffic — 3 concurrent requests is a safe default.

        Args:
            ports: List of port dicts to enrich.
            api_key: NVD API key (optional but recommended).
            os_name: OS hint string for better CVE matching.
            max_concurrent: Max concurrent NVD requests (default 3).
        """
        open_ports = [p for p in ports if "open" in p["state"] and p.get("service")]
        if not open_ports:
            return ports

        # إنشاء الـ Semaphore للتحكم في عدد الطلبات المتزامنة
        sem = asyncio.Semaphore(max_concurrent)

        # دالة مساعدة لتغليف الاستعلام بالـ Semaphore
        async def safe_query(coro):
            async with sem:
                return await coro

        tasks = []
        for p in open_ports:
            cpe_value = p.get("cpe", "") or ""
            if cpe_value:
                coro = cls.query("", api_key, cpe=cpe_value, os_name=os_name)
            else:
                query_key = " ".join(filter(None, [p.get("service", ""), p.get("version", ""), os_name or ""]))
                coro = cls.query(query_key, api_key, cpe="", os_name=os_name)

            # بنغلف الـ coroutine بالـ safe_query اللي بتجبره يحترم الـ Semaphore
            tasks.append(safe_query(coro))

        # تشغيل المهام مع التحكم في التزامن
        results = await asyncio.gather(*tasks)

        for port, cves in zip(open_ports, results):
            port["cves"] = cves
        return ports

    @classmethod
    def compute_confidence(cls, keyword: str, description: str, os_name: str = "") -> float:
        text = (description or "").lower()
        keyword_terms = {t for t in re.findall(r"[A-Za-z0-9]+", (keyword or "").lower()) if len(t) >= 3}
        os_terms = {t for t in re.findall(r"[A-Za-z0-9]+", os_name.lower()) if len(t) >= 3}
        terms = keyword_terms | os_terms

        if not terms:
            return 0.15

        desc_tokens = {t for t in re.findall(r"[A-Za-z0-9]+", text)}
        exact_matches = sum(1 for term in terms if term in desc_tokens)
        substring_matches = sum(1 for term in terms if term not in desc_tokens and term in text)

        if exact_matches > 0:
            score = 0.45 + 0.12 * exact_matches
        elif substring_matches > 0:
            score = 0.30 + 0.10 * substring_matches
        else:
            score = 0.20

        return round(min(0.95, score), 2)
