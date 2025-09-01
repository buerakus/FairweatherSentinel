from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple

import json
import os
import time
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/{}"
CACHE_FILE = ".nvd_cache.json"
CACHE_TTL  = 60 * 60 * 24

def _load_cache() -> Dict[str, Any]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _get_cvss_from_nvd(cve_id: str) -> float | None:
    cache: Dict[str, Any] = _load_cache()
    now = time.time()

    if cve_id in cache and now - cache[cve_id]["timestamp"] < CACHE_TTL:
        return cache[cve_id]["score"]

    try:
        with urllib.request.urlopen(NVD_URL.format(cve_id)) as resp:
            data = json.loads(resp.read())
            metrics = data["result"]["CVE_Items"][0]["metrics"]

            # Try CVSS v3 first
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV3" in metrics:
                score = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            else:
                score = None
    except Exception:
        score = None  # network issue or unknown CVE

    cache[cve_id] = {"score": score, "timestamp": now}
    _save_cache(cache)
    return score

def severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"

def analyze_results(raw: List[Dict[str, Any]]
                    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:


    enriched: List[Dict[str, Any]] = []
    sev_counter: Counter = Counter()
    risk_by_service: Counter = Counter()

    for finding in raw:
        entry = finding.copy()  # don’t mutate caller data

        cvss = entry.get("cvss")
        cve  = entry.get("cve")

        if cvss is None and cve:
            cvss = _get_cvss_from_nvd(cve)
            entry["cvss"] = cvss


        entry["severity"] = severity_label(cvss)
        entry["analyzed_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        enriched.append(entry)

        sev_counter[entry["severity"]] += 1
        key = f"{entry.get('service','unknown')}:{entry.get('port','?')}"
        risk_by_service[key] += cvss or 0

    most_risky = risk_by_service.most_common(3)
    summary = {
        "counts_by_severity": dict(sev_counter),
        "top_risky_services": most_risky,
        "total_findings": len(enriched),
    }

    return enriched, summary

if __name__ == "__main__":
    # quick self‑test
    sample = [
        {"port": 22, "service": "ssh",  "vulnerability": "Weak SSH key",
         "cve": "CVE-2016-0777"},
        {"port": 80, "service": "http", "vulnerability": "Outdated Apache",
         "cve": "CVE-2021-41773", "cvss": 7.4},
        {"port": 139, "service": "samba", "vulnerability": "SMBv1 enabled",
         "cvss": 5.0},
    ]
    enriched, stats = analyze_results(sample)
    print(json.dumps(enriched, indent=2))
    print("\nSummary:", stats)
