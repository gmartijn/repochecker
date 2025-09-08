#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pypi_audit.py
Audits one or more PyPI packages for quality & supply‑chain risk signals and
produces a weighted trust score (0‑100).

Usage:
    python pypi_audit.py <package> [<package> ...] [options]

Key options:
    --pretty            Pretty print stdout JSON.
    --json              Only write results to pypi_audit.json (no console summary).
    --score-details     Include per-metric breakdown in file output (always present internally).
    --timeout N         HTTP timeout (default 15s).
    --no-osv            Skip OSV vulnerability lookup.
    --fail-below X      Exit non‑zero if any package score < X (0‑100).

Examples:
    python pypi_audit.py requests --pretty
    python pypi_audit.py fastapi uvicorn --pretty --timeout 20 --fail-below 70
    python pypi_audit.py numpy --json --score-details
"""

import argparse
import datetime as dt
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("This script requires the 'requests' package. Try: pip install requests", file=sys.stderr)
    sys.exit(2)

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# ---------- Scoring Weights (tweak as you like) ----------
WEIGHTS = {
    "recent_release": 15,         # recency of latest release
    "release_cadence": 10,        # number of releases in last 365 days
    "has_license": 10,
    "license_osi_approved": 5,
    "has_requires_python": 8,
    "dev_status": 8,              # from trove classifiers
    "has_readme": 5,
    "maintainer_present": 5,
    "wheels_present": 8,
    "manylinux_or_abi3": 4,
    "py3_wheel": 4,
    "project_urls": 5,
    "ci_badge_hint": 2,
    "dep_count_reasonable": 5,    # penalize extremes
    "vulns_known_none": 6,        # reward if no known OSV vulns
}

# Risk level (inverse) retained for backwards compatibility; higher % = lower risk
RISK_THRESHOLDS = [
    (85, "Low"),
    (70, "Moderate"),
    (50, "Elevated"),
    (30, "High"),
    (0,  "Critical"),
]

# Docker-style trust levels (higher % => stronger trust)
def trust_level(percent: float) -> str:
    if percent >= 90:
        return "Critical"
    if percent >= 75:
        return "High"
    if percent >= 50:
        return "Medium"
    if percent >= 25:
        return "Low"
    return "Very Low"

DEV_STATUS_POINTS = {
    # Trove: "Development Status :: X - Label"
    # Map to a 0..1 scale we’ll multiply by weight
    "1 - Planning": 0.2,
    "2 - Pre-Alpha": 0.2,
    "3 - Alpha": 0.4,
    "4 - Beta": 0.6,
    "5 - Production/Stable": 1.0,
    "6 - Mature": 1.0,
    "7 - Inactive": 0.1,
}

OSI_LICENSE_HINTS = [
    # Not exhaustive—just common strings found in classifiers or license field
    "Apache Software License",
    "MIT License",
    "BSD License",
    "GNU General Public License",
    "GNU Lesser General Public License",
    "Mozilla Public License",
    "ISC License",
    "Python Software Foundation License",
    "Academic Free License",
    "Artistic License",
    "Eclipse Public License",
]

CI_BADGE_PATTERNS = [
    r"badge\.fury\.io",
    r"shields\.io",
    r"github\.com/.+/actions",
    r"travis-ci\.org",
    r"travis-ci\.com",
    r"circleci\.com",
    r"appveyor\.com",
    r"gitlab\.com/.+/-/pipelines",
]

@dataclass
class Metric:
    name: str
    value: Any
    weight: int
    score: float
    comment: str

def make_session(timeout: int) -> requests.Session:
    sess = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.request = _timeout_request_wrapper(sess.request, timeout)
    return sess

def _timeout_request_wrapper(func, timeout: int):
    def wrapped(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return func(method, url, **kwargs)
    return wrapped

def get_json(sess: requests.Session, url: str, method: str = "GET", payload: Optional[dict] = None) -> Optional[dict]:
    try:
        if method == "GET":
            r = sess.get(url)
        else:
            r = sess.post(url, json=payload or {})
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None

def fetch_pypi_metadata(sess: requests.Session, name: str) -> Optional[dict]:
    return get_json(sess, PYPI_JSON_URL.format(name=name))

def parse_latest_release_date(data: dict) -> Optional[dt.datetime]:
    releases = data.get("releases") or {}
    latest_dt = None
    for files in releases.values():
        for f in files or []:
            up = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not up:
                continue
            try:
                # PyPI times are UTC ISO 8601, may end with 'Z'
                up_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
            except Exception:
                continue
            if (latest_dt is None) or (up_dt > latest_dt):
                latest_dt = up_dt
    # Fallback to info.upload_time if needed (rare)
    if latest_dt is None:
        info = data.get("info") or {}
        up = info.get("upload_time_iso_8601") or info.get("upload_time")
        if up:
            try:
                latest_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
            except Exception:
                latest_dt = None
    return latest_dt

def releases_in_last_days(data: dict, days: int = 365) -> int:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    releases = data.get("releases") or {}
    seen_versions = 0
    for ver, files in releases.items():
        latest_for_ver = None
        for f in files or []:
            up = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not up:
                continue
            try:
                up_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
            except Exception:
                continue
            if latest_for_ver is None or up_dt > latest_for_ver:
                latest_for_ver = up_dt
        if latest_for_ver and latest_for_ver >= cutoff:
            seen_versions += 1
    return seen_versions

def detect_license(info: dict) -> Tuple[bool, bool, str]:
    # Return (has_license, looks_osi, raw)
    raw = (info.get("license") or "").strip()
    classifiers = info.get("classifiers") or []
    has = False
    looks_osi = False

    # Classifiers are most reliable
    for c in classifiers:
        if c.startswith("License ::"):
            has = True
            for hint in OSI_LICENSE_HINTS:
                if hint in c:
                    looks_osi = True
                    break

    if not has and raw:
        has = True
        # crude heuristic for OSI-ish
        for hint in OSI_LICENSE_HINTS + ["Apache", "MIT", "BSD", "GPL", "LGPL", "MPL", "ISC", "EPL"]:
            if hint.lower() in raw.lower():
                looks_osi = True
                break

    return has, looks_osi, raw or "unknown"

def dev_status_score(info: dict) -> Tuple[float, str]:
    classifiers = info.get("classifiers") or []
    status_label = None
    for c in classifiers:
        if c.startswith("Development Status ::"):
            # c like "Development Status :: 5 - Production/Stable"
            parts = c.split("::")[-1].strip()
            status_label = parts
            break
    if not status_label:
        return 0.5, "Unknown"  # neutral-ish
    # map
    points = 0.5
    for key, val in DEV_STATUS_POINTS.items():
        if key in status_label:
            points = val
            break
    return points, status_label

def readme_present(info: dict) -> bool:
    desc = info.get("description") or ""
    # Description often contains the long README (reST/Markdown)
    return len(desc.strip()) >= 200  # heuristic

def maintainer_present(info: dict) -> bool:
    # PyPI JSON doesn’t list a maintainer roster; we use these hints
    fields = [
        info.get("maintainer"), info.get("maintainer_email"),
        info.get("author"), info.get("author_email"),
    ]
    return any(bool((f or "").strip()) for f in fields)

def project_urls_present(info: dict) -> bool:
    urls = info.get("project_urls") or {}
    if urls:
        return True
    # Fallbacks
    return bool((info.get("home_page") or "").strip() or (info.get("project_url") or "").strip())

def has_ci_badge(info: dict) -> bool:
    text = (info.get("description") or "") + " " + " ".join((info.get("project_urls") or {}).values())
    text_lower = text.lower()
    for pat in CI_BADGE_PATTERNS:
        if re.search(pat, text_lower):
            return True
    return False

def wheel_presence(data: dict) -> Tuple[bool, bool, bool]:
    """
    Returns (has_any_wheel, has_manylinux_or_abi3, has_py3_wheel) for the latest version only.
    """
    info = data.get("info") or {}
    version = info.get("version")
    releases = data.get("releases") or {}
    files = releases.get(version) or []
    has_wheel = False
    manylinux_or_abi3 = False
    py3_wheel = False
    for f in files:
        fn = f.get("filename") or ""
        packagetype = f.get("packagetype")
        if packagetype == "bdist_wheel" or fn.endswith(".whl"):
            has_wheel = True
            # simple hints
            if "manylinux" in fn.lower() or "abi3" in fn.lower():
                manylinux_or_abi3 = True
            if "py3" in fn.lower() or "cp3" in fn.lower():
                py3_wheel = True
    return has_wheel, manylinux_or_abi3, py3_wheel

def dependency_count(info: dict) -> int:
    reqs = info.get("requires_dist") or []
    return len(reqs)

def osv_vulnerability_count(sess: requests.Session, package: str) -> Optional[int]:
    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI",
        }
    }
    data = get_json(sess, OSV_QUERY_URL, method="POST", payload=payload)
    if not data:
        return None
    vulns = data.get("vulns") or []
    return len(vulns)

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def score_package(sess: requests.Session, name: str, include_osv: bool = True) -> Dict[str, Any]:
    meta = fetch_pypi_metadata(sess, name)
    if not meta:
        return {
            "package": name,
            "collected_at": dt.datetime.utcnow().isoformat() + "Z",
            "error": "Package not found or PyPI unreachable."
        }

    info = meta.get("info") or {}
    metrics: List[Metric] = []

    # 1) Recency of latest release
    latest_dt = parse_latest_release_date(meta)
    if latest_dt:
        days = (dt.datetime.now(dt.timezone.utc) - latest_dt).days
        # 0 days -> full points; 365+ -> near 0
        recency_factor = clamp(1 - days / 365.0, 0, 1)
        score = recency_factor * WEIGHTS["recent_release"]
        comment = f"Last release {days} days ago ({latest_dt.date().isoformat()})."
    else:
        score = 0
        comment = "No release date found."
        days = None
    metrics.append(Metric("recent_release", days if days is not None else "unknown",
                          WEIGHTS["recent_release"], round(score, 2), comment))

    # 2) Release cadence (versions in last year)
    rels_year = releases_in_last_days(meta, 365)
    # 0 -> 0, >=6 -> full points (tweak)
    cadence_factor = clamp(rels_year / 6.0, 0, 1)
    metrics.append(Metric("release_cadence_last_365d", rels_year, WEIGHTS["release_cadence"],
                          round(cadence_factor * WEIGHTS["release_cadence"], 2),
                          f"{rels_year} release(s) in the last 365 days."))

    # 3) License & OSI-ish license
    has_lic, looks_osi, raw_lic = detect_license(info)
    metrics.append(Metric("license_present", raw_lic, WEIGHTS["has_license"],
                          WEIGHTS["has_license"] if has_lic else 0,
                          "License detected." if has_lic else "No clear license found."))
    metrics.append(Metric("license_osi_approved_hint", looks_osi, WEIGHTS["license_osi_approved"],
                          WEIGHTS["license_osi_approved"] if looks_osi else 0,
                          "OSI-style license suggested by classifiers/text." if looks_osi else "License may not be OSI-approved or is unclear."))

    # 4) Requires-Python pin
    rp = info.get("requires_python")
    metrics.append(Metric("requires_python_present", rp or "none", WEIGHTS["has_requires_python"],
                          WEIGHTS["has_requires_python"] if rp else 0,
                          "Requires-Python specified." if rp else "No Python version constraint specified."))

    # 5) Development status
    dev_pts, dev_label = dev_status_score(info)
    metrics.append(Metric("development_status", dev_label, WEIGHTS["dev_status"],
                          round(dev_pts * WEIGHTS["dev_status"], 2),
                          f"Classifier indicates: {dev_label}."))

    # 6) README/long description presence
    has_md = readme_present(info)
    metrics.append(Metric("readme_present", has_md, WEIGHTS["has_readme"],
                          WEIGHTS["has_readme"] if has_md else 0,
                          "Project has a substantial long description." if has_md else "Long description appears thin or missing."))

    # 7) Maintainer/author presence (bus factor hint)
    maint_ok = maintainer_present(info)
    metrics.append(Metric("maintainer_present", maint_ok, WEIGHTS["maintainer_present"],
                          WEIGHTS["maintainer_present"] if maint_ok else 0,
                          "Maintainer/author metadata present." if maint_ok else "Maintainer/author fields missing."))

    # 8) Wheels presence
    has_wheel, has_manylinux_or_abi3, has_py3 = wheel_presence(meta)
    metrics.append(Metric("latest_has_wheel", has_wheel, WEIGHTS["wheels_present"],
                          WEIGHTS["wheels_present"] if has_wheel else 0,
                          "Wheel available for latest version." if has_wheel else "Latest version appears sdist-only."))
    metrics.append(Metric("manylinux_or_abi3", has_manylinux_or_abi3, WEIGHTS["manylinux_or_abi3"],
                          WEIGHTS["manylinux_or_abi3"] if has_manylinux_or_abi3 else 0,
                          "Wheel suggests manylinux/abi3 compatibility." if has_manylinux_or_abi3 else "No manylinux/abi3 hint detected."))
    metrics.append(Metric("py3_wheel", has_py3, WEIGHTS["py3_wheel"],
                          WEIGHTS["py3_wheel"] if has_py3 else 0,
                          "Python 3 wheel present." if has_py3 else "No explicit py3 wheel tag detected."))

    # 9) Project URLs
    urls_ok = project_urls_present(info)
    metrics.append(Metric("project_urls_present", urls_ok, WEIGHTS["project_urls"],
                          WEIGHTS["project_urls"] if urls_ok else 0,
                          "Project URLs available (homepage/repo/docs)." if urls_ok else "No project URLs declared."))

    # 10) CI badge hint
    ci_hint = has_ci_badge(info)
    metrics.append(Metric("ci_badge_hint", ci_hint, WEIGHTS["ci_badge_hint"],
                          WEIGHTS["ci_badge_hint"] if ci_hint else 0,
                          "CI or quality badges referenced." if ci_hint else "No CI/quality badge hints found."))

    # 11) Dependency count (reward moderate counts, penalize extremes)
    dep_cnt = dependency_count(info)
    # Heuristic: sweet spot 0-25; clamp beyond 50
    if dep_cnt == 0:
        dep_factor = 0.8
        dep_comment = "No declared runtime dependencies."
    elif dep_cnt <= 25:
        dep_factor = 1.0
        dep_comment = f"{dep_cnt} declared dependencies (reasonable)."
    elif dep_cnt <= 50:
        dep_factor = 0.6
        dep_comment = f"{dep_cnt} dependencies (somewhat heavy)."
    else:
        dep_factor = 0.3
        dep_comment = f"{dep_cnt} dependencies (heavy)."
    metrics.append(Metric("dependency_count_reasonable", dep_cnt, WEIGHTS["dep_count_reasonable"],
                          round(dep_factor * WEIGHTS["dep_count_reasonable"], 2), dep_comment))

    # 12) OSV known vulnerabilities (optional)
    osv_count = None
    if include_osv:
        osv_count = osv_vulnerability_count(sess, name)
    if include_osv and osv_count is not None:
        if osv_count == 0:
            osv_score = WEIGHTS["vulns_known_none"]
            osv_comment = "No known OSV vulnerabilities."
        else:
            # Linear penalty: 0 when >= 5 vulns
            osv_factor = clamp(1 - (osv_count / 5.0), 0, 1)
            osv_score = round(osv_factor * WEIGHTS["vulns_known_none"], 2)
            osv_comment = f"{osv_count} known OSV vulnerability(ies) found."
        metrics.append(Metric("vulnerabilities_known_osv", osv_count, WEIGHTS["vulns_known_none"], osv_score, osv_comment))
    else:
        metrics.append(Metric("vulnerabilities_known_osv", "skipped", WEIGHTS["vulns_known_none"], 0,
                              "OSV check skipped or unavailable."))

    # Aggregate
    score_total = round(sum(m.score for m in metrics), 2)
    score_max = sum(m.weight for m in metrics)
    percent = round((score_total / score_max) * 100, 1) if score_max else 0.0
    risk = next(label for thresh, label in RISK_THRESHOLDS if percent >= thresh)

    # Helpful high-level comments
    highlights = []
    if latest_dt:
        if (dt.datetime.now(dt.timezone.utc) - latest_dt).days <= 120:
            highlights.append("Active releases in the last 4 months.")
    if has_wheel and has_py3:
        highlights.append("Pre-built Python 3 wheels available.")
    if has_lic and looks_osi:
        highlights.append("Clear OSI-style license.")
    if rp:
        highlights.append(f"Requires-Python set: {rp}.")
    if urls_ok:
        highlights.append("Project URLs present (repo/docs/homepage).")
    if dep_cnt > 50:
        highlights.append("Heavy dependency footprint—review needed.")
    if include_osv and (osv_count not in (None, 0)):
        highlights.append("Known vulnerabilities present—investigate advisories.")

    return {
        "package": name,
        # timezone aware ISO8601
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "score_total": score_total,
        "score_max": score_max,
        "score_percent": percent,
        "risk_level": risk,           # legacy naming (inverse risk)
        "trust_level": trust_level(percent),  # aligned with docker audit semantics
        "percentage": percent,        # alias for docker style key
        "info": {
            "name": info.get("name"),
            "summary": info.get("summary"),
            "version": info.get("version"),
            "home_page": info.get("home_page"),
            "project_urls": info.get("project_urls"),
        },
        "metrics": [asdict(m) for m in metrics],
        "highlights": highlights,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Audit PyPI packages for trust & risk signals (Docker-style scoring)."
    )
    parser.add_argument("packages", nargs="+", help="One or more PyPI package names.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--json", action="store_true", help="Write only to pypi_audit.json (suppress console summary).")
    parser.add_argument("--score-details", action="store_true", help="Include per-metric breakdown in top-level output (always stored internally).")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15).")
    parser.add_argument("--no-osv", action="store_true", help="Skip OSV vulnerability check.")
    parser.add_argument("--fail-below", type=float, metavar="SCORE", help="Exit 1 if any package score < SCORE (0-100).")
    parser.add_argument("--exit-risk-code", action="store_true", help="Exit with code based on WORST package trust level (Critical=0, High=1, Medium=2, Low=3, Very Low=4, Error=10).")
    args = parser.parse_args()

    sess = make_session(timeout=args.timeout)
    results = []
    fail_hits = []
    for pkg in args.packages:
        res = score_package(sess, pkg, include_osv=not args.no_osv)
        results.append(res)
        if args.fail_below is not None and res.get("score_percent", 0) < args.fail_below:
            fail_hits.append(pkg)

    # Prepare output payload
    payload = results if len(results) > 1 else results[0]
    if not args.score_details:
        # For brevity, remove raw metrics if user didn't request details (still in file if --score-details)
        if isinstance(payload, dict):
            payload_no_metrics = dict(payload)
            payload_no_metrics.pop("metrics", None)
            payload = payload_no_metrics
        else:  # list
            trimmed = []
            for item in payload:
                c = dict(item)
                c.pop("metrics", None)
                trimmed.append(c)
            payload = trimmed

    # Console output
    if not args.json:
        if isinstance(results, list):
            # Summary line for each
            for r in results:
                print(f"Package: {r['package']} | Trust: {r['trust_level']} | Score: {r['score_percent']}%")
        else:
            r = results[0]
            print(f"Package: {r['package']} | Trust: {r['trust_level']} | Score: {r['score_percent']}%")
        print()
        if args.pretty:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(payload, ensure_ascii=False))

    # Write file (always full results including metrics regardless of --score-details)
    try:
        with open("pypi_audit.json", "w", encoding="utf-8") as f:
            json.dump(results if len(results) > 1 else results[0], f, indent=2, ensure_ascii=False)
        if not args.json:
            print("\n✅ Results written to pypi_audit.json")
    except Exception as e:
        if not args.json:
            print(f"\n❌ Failed to write pypi_audit.json: {e}")

    # Fail-below logic
    if args.fail_below is not None:
        if fail_hits:
            if not args.json:
                print(f"\n❌ Packages below threshold {args.fail_below}: {', '.join(fail_hits)}")
            sys.exit(1)
        else:
            if not args.json:
                print(f"\n✅ All packages meet threshold {args.fail_below}.")
            sys.exit(0)

    # Exit code mapping (only if --exit-risk-code and fail-below not triggered)
    if args.exit_risk_code:
        level_to_code = {
            # Here 'Critical' means highest trust (>=90) per this script's naming convention
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Very Low": 4,
        }
        # Determine worst (highest numeric code) across all packages
        worst_code = -1
        worst_level = None
        worst_pkg = None
        for r in results:
            lvl = r.get("trust_level")
            code = level_to_code.get(lvl, 10)
            if code > worst_code:
                worst_code = code
                worst_level = lvl
                worst_pkg = r.get("package")
        if not args.json:
            print(f"\nℹ️  Exiting with code {worst_code} (worst package: {worst_pkg} trust level: {worst_level}).")
        # Use 10 for unexpected/unknown trust level or error
        sys.exit(worst_code if worst_code >= 0 else 10)

if __name__ == "__main__":
    main()