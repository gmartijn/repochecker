#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pypi_audit.py
pypi_audit.py
Audits PyPI packages, writes JSON to a file by default, and prints a TL;DR breakdown.
INVERTED MODEL: Lower percent = better (safer). Higher percent = worse (riskier).

Risk display: [VERY LOW], [LOW], [MEDIUM], [HIGH], [CRITICAL]

Usage:
  python pypi_audit.py <package> [<package> ...]
    [--file packages.txt]
    [--pretty] [--timeout 15] [--no-osv]
    [--fail-above 70] [--fail-below 85]   # fail-above uses RISK %, fail-below uses HEALTH %
    [--out report.json]
    [--no-tldr]
    [--stdout-json]

Notes:
- Package arguments may include version pins, e.g. `requests==2.31.0` or `packaging==16.8`.
- Extras/specifiers like `foo[bar]==1.0` are accepted; extras are ignored for metadata fetch.
- If an exact version is pinned (== or ===), wheel/recency checks and OSV queries target that version.

Exit codes:
  0 = success
  1 = operational error (e.g., fetch failed, bad args, write error)
  2 = quality gate failed
"""

import argparse
import datetime as dt
import json
import os
import re
import sys
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

# ---------- Metric Weights ----------
WEIGHTS = {
    "recent_release": 15,
    "release_cadence": 10,
    "has_license": 10,
    "license_osi_approved": 5,
    "has_requires_python": 8,
    "dev_status": 8,
    "has_readme": 5,
    "maintainer_present": 5,
    "wheels_present": 8,
    "manylinux_or_abi3": 4,
    "py3_wheel": 4,
    "project_urls": 5,
    "ci_badge_hint": 2,
    "dep_count_reasonable": 5,
    "vulns_known_none": 6,
}

# Inverted risk thresholds (higher percent = worse).
# Returns label, [DISPLAY], rank (1 best .. 5 worst).
RISK_THRESHOLDS_INVERTED = [
    (15, ("Very Low",  "[VERY LOW]", 1)),
    (30, ("Low",       "[LOW]",      2)),
    (50, ("Medium",    "[MEDIUM]",   3)),
    (70, ("High",      "[HIGH]",     4)),
    (100,("Critical",  "[CRITICAL]", 5)),
]

DEV_STATUS_POINTS = {
    "1 - Planning": 0.2,
    "2 - Pre-Alpha": 0.2,
    "3 - Alpha": 0.4,
    "4 - Beta": 0.6,
    "5 - Production/Stable": 1.0,
    "6 - Mature": 1.0,
    "7 - Inactive": 0.1,
}

OSI_LICENSE_HINTS = [
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

# ---------- Version parsing helpers ----------

_SPEC_SPLIT_RE = re.compile(
    r"""^\s*
        (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
        (?:\[[^\]]*\])?                 # optional extras, ignored
        \s*
        (?:
            (?P<op>===|==|!=|~=|>=|<=|>|<)
            \s*
            (?P<ver>[A-Za-z0-9][A-Za-z0-9._+-]*)
        )?
        \s*$
    """,
    re.VERBOSE,
)

def parse_name_and_exact_version(s: str) -> Tuple[str, Optional[str]]:
    """
    Returns (name, exact_version or None). Only returns a version if operator is == or ===.
    Accepts extras like 'pkg[extra]==1.2' and ignores the extras.
    If the string doesn't match, fallback to treating the whole string as the name.
    """
    m = _SPEC_SPLIT_RE.match(s)
    if not m:
        # Fallback: strip anything after first specifier char
        name = re.split(r"[<>=!~\s]", s, 1)[0]
        return name, None
    name = m.group("name")
    op = m.group("op")
    ver = m.group("ver")
    if op in ("==", "===") and ver:
        return name, ver
    return name, None

# ---------- Data classes ----------

@dataclass
class Metric:
    name: str
    value: Any
    weight: int
    score: float
    comment: str

# ---------- Networking ----------

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
        r = sess.get(url) if method == "GET" else sess.post(url, json=payload or {})
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None

def fetch_pypi_metadata(sess: requests.Session, name: str) -> Optional[dict]:
    return get_json(sess, PYPI_JSON_URL.format(name=name))

# ---------- Helpers over PyPI JSON ----------

def parse_latest_release_date(data: dict) -> Optional[dt.datetime]:
    releases = data.get("releases") or {}
    latest_dt = None
    for files in releases.values():
        for f in files or []:
            up = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not up:
                continue
            try:
                up_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
            except Exception:
                continue
            if (latest_dt is None) or (up_dt > latest_dt):
                latest_dt = up_dt
    if latest_dt is None:
        info = data.get("info") or {}
        up = info.get("upload_time_iso_8601") or info.get("upload_time")
        if up:
            try:
                latest_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
            except Exception:
                latest_dt = None
    return latest_dt

def release_date_for_version(data: dict, version: str) -> Optional[dt.datetime]:
    releases = data.get("releases") or {}
    files = releases.get(version) or []
    latest_dt = None
    for f in files:
        up = f.get("upload_time_iso_8601") or f.get("upload_time")
        if not up:
            continue
        try:
            up_dt = dt.datetime.fromisoformat(up.replace("Z", "+00:00"))
        except Exception:
            continue
        if (latest_dt is None) or (up_dt > latest_dt):
            latest_dt = up_dt
    return latest_dt

def releases_in_last_days(data: dict, days: int = 365) -> int:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    releases = data.get("releases") or {}
    seen_versions = 0
    for _, files in releases.items():
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
    raw = (info.get("license") or "").strip()
    classifiers = info.get("classifiers") or []
    has = False
    looks_osi = False
    for c in classifiers:
        if c.startswith("License ::"):
            has = True
            for hint in OSI_LICENSE_HINTS:
                if hint in c:
                    looks_osi = True
                    break
    if not has and raw:
        has = True
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
            status_label = c.split("::")[-1].strip()
            break
    if not status_label:
        return 0.5, "Unknown"
    points = 0.5
    for key, val in DEV_STATUS_POINTS.items():
        if key in status_label:
            points = val
            break
    return points, status_label

def readme_present(info: dict) -> bool:
    desc = info.get("description") or ""
    return len(desc.strip()) >= 200

def maintainer_present(info: dict) -> bool:
    fields = [
        info.get("maintainer"), info.get("maintainer_email"),
        info.get("author"), info.get("author_email"),
    ]
    return any(bool((f or "").strip()) for f in fields)

def project_urls_present(info: dict) -> bool:
    urls = info.get("project_urls") or {}
    if urls:
        return True
    return bool((info.get("home_page") or "").strip() or (info.get("project_url") or "").strip())

def has_ci_badge(info: dict) -> bool:
    text = (info.get("description") or "") + " " + " ".join((info.get("project_urls") or {}).values())
    text_lower = text.lower()
    for pat in CI_BADGE_PATTERNS:
        if re.search(pat, text_lower):
            return True
    return False

def wheel_presence_for_version(data: dict, version: Optional[str]) -> Tuple[bool, bool, bool]:
    info = data.get("info") or {}
    ver = version or info.get("version")
    releases = data.get("releases") or {}
    files = releases.get(ver) or []
    has_wheel = False
    manylinux_or_abi3 = False
    py3_wheel = False
    for f in files:
        fn = (f.get("filename") or "")
        packagetype = f.get("packagetype")
        if packagetype == "bdist_wheel" or fn.endswith(".whl"):
            has_wheel = True
            fl = fn.lower()
            if "manylinux" in fl or "abi3" in fl:
                manylinux_or_abi3 = True
            if "py3" in fl or "cp3" in fl:
                py3_wheel = True
    return has_wheel, manylinux_or_abi3, py3_wheel

def dependency_count(info: dict) -> int:
    reqs = info.get("requires_dist") or []
    return len(reqs)

def osv_vulnerability_count(sess: requests.Session, package: str, version: Optional[str]) -> Optional[int]:
    payload = {"package": {"name": package, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version
    data = get_json(sess, OSV_QUERY_URL, method="POST", payload=payload)
    if not data:
        return None
    vulns = data.get("vulns") or []
    return len(vulns)

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def risk_tuple_from_percent(risk_percent: float) -> Tuple[str, str, int]:
    for threshold, tup in RISK_THRESHOLDS_INVERTED:
        if risk_percent <= threshold:
            return tup
    return ("Critical", "[CRITICAL]", 5)

# ---------- Scoring ----------

def score_one(meta: dict, include_osv: bool, sess: requests.Session, name: str, exact_version: Optional[str]) -> Dict[str, Any]:
    info = meta.get("info") or {}
    metrics: List[Metric] = []

    # Recency: if version pinned, use that version's upload date; else latest across all.
    if exact_version:
        vdt = release_date_for_version(meta, exact_version)
        if vdt:
            days = (dt.datetime.now(dt.timezone.utc) - vdt).days
            recency_factor = clamp(1 - days / 365.0, 0, 1)
            score = recency_factor * WEIGHTS["recent_release"]
            comment = f"Version {exact_version} released {days} days ago ({vdt.date().isoformat()})."
        else:
            days = None
            score = 0
            comment = f"Version {exact_version} not found in releases."
    else:
        latest_dt = parse_latest_release_date(meta)
        if latest_dt:
            days = (dt.datetime.now(dt.timezone.utc) - latest_dt).days
            recency_factor = clamp(1 - days / 365.0, 0, 1)
            score = recency_factor * WEIGHTS["recent_release"]
            comment = f"Last release {days} days ago ({latest_dt.date().isoformat()})."
        else:
            score = 0
            comment = "No release date found."
            days = None

    metrics.append(Metric("recent_release", days if days is not None else "unknown",
                          WEIGHTS["recent_release"], round(score, 2), comment))

    # Cadence still based on the project overall (not just one pinned version)
    rels_year = releases_in_last_days(meta, 365)
    cadence_factor = clamp(rels_year / 6.0, 0, 1)
    metrics.append(Metric("release_cadence_last_365d", rels_year, WEIGHTS["release_cadence"],
                          round(cadence_factor * WEIGHTS["release_cadence"], 2),
                          f"{rels_year} release(s) in the last 365 days."))

    has_lic, looks_osi, raw_lic = detect_license(info)
    metrics.append(Metric("license_present", raw_lic, WEIGHTS["has_license"],
                          WEIGHTS["has_license"] if has_lic else 0,
                          "License detected." if has_lic else "No clear license found."))
    metrics.append(Metric("license_osi_approved_hint", looks_osi, WEIGHTS["license_osi_approved"],
                          WEIGHTS["license_osi_approved"] if looks_osi else 0,
                          "OSI-style license suggested by classifiers/text." if looks_osi else "License may not be OSI-approved or is unclear."))

    rp = info.get("requires_python")
    metrics.append(Metric("requires_python_present", rp or "none", WEIGHTS["has_requires_python"],
                          WEIGHTS["has_requires_python"] if rp else 0,
                          "Requires-Python specified." if rp else "No Python version constraint specified."))

    dev_pts, dev_label = dev_status_score(info)
    metrics.append(Metric("development_status", dev_label, WEIGHTS["dev_status"],
                          round(dev_pts * WEIGHTS["dev_status"], 2),
                          f"Classifier indicates: {dev_label}."))

    has_md = readme_present(info)
    metrics.append(Metric("readme_present", has_md, WEIGHTS["has_readme"],
                          WEIGHTS["has_readme"] if has_md else 0,
                          "Project has a substantial long description." if has_md else "Long description appears thin or missing."))

    maint_ok = maintainer_present(info)
    metrics.append(Metric("maintainer_present", maint_ok, WEIGHTS["maintainer_present"],
                          WEIGHTS["maintainer_present"] if maint_ok else 0,
                          "Maintainer/author metadata present." if maint_ok else "Maintainer/author fields missing."))

    has_wheel, has_manylinux_or_abi3, has_py3 = wheel_presence_for_version(meta, exact_version)
    metrics.append(Metric("latest_has_wheel" if not exact_version else "pinned_has_wheel",
                          has_wheel, WEIGHTS["wheels_present"],
                          WEIGHTS["wheels_present"] if has_wheel else 0,
                          ("Wheel available for evaluated version." if exact_version else "Wheel available for latest version.")
                          if has_wheel else
                          ("Evaluated version appears sdist-only." if exact_version else "Latest version appears sdist-only.")))
    metrics.append(Metric("manylinux_or_abi3", has_manylinux_or_abi3, WEIGHTS["manylinux_or_abi3"],
                          WEIGHTS["manylinux_or_abi3"] if has_manylinux_or_abi3 else 0,
                          "Wheel suggests manylinux/abi3 compatibility." if has_manylinux_or_abi3 else "No manylinux/abi3 hint detected."))
    metrics.append(Metric("py3_wheel", has_py3, WEIGHTS["py3_wheel"],
                          WEIGHTS["py3_wheel"] if has_py3 else 0,
                          "Python 3 wheel present." if has_py3 else "No explicit py3 wheel tag detected."))

    urls_ok = project_urls_present(info)
    metrics.append(Metric("project_urls_present", urls_ok, WEIGHTS["project_urls"],
                          WEIGHTS["project_urls"] if urls_ok else 0,
                          "Project URLs available (homepage/repo/docs)." if urls_ok else "No project URLs declared."))

    ci_hint = has_ci_badge(info)
    metrics.append(Metric("ci_badge_hint", ci_hint, WEIGHTS["ci_badge_hint"],
                          WEIGHTS["ci_badge_hint"] if ci_hint else 0,
                          "CI or quality badges referenced." if ci_hint else "No CI/quality badge hints found."))

    dep_cnt = dependency_count(info)
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

    osv_count = None
    if include_osv:
        osv_count = osv_vulnerability_count(sess, name, exact_version)
    if include_osv and osv_count is not None:
        if osv_count == 0:
            osv_score = WEIGHTS["vulns_known_none"]
            osv_comment = "No known OSV vulnerabilities."
        else:
            osv_factor = clamp(1 - (osv_count / 5.0), 0, 1)
            osv_score = round(osv_factor * WEIGHTS["vulns_known_none"], 2)
            osv_comment = f"{osv_count} known OSV vulnerability(ies) found."
        metrics.append(Metric("vulnerabilities_known_osv", osv_count, WEIGHTS["vulns_known_none"], osv_score, osv_comment))
    else:
        metrics.append(Metric("vulnerabilities_known_osv", "skipped", WEIGHTS["vulns_known_none"], 0,
                              "OSV check skipped or unavailable."))

    # Aggregate -> percent
    score_total_good = round(sum(m.score for m in metrics), 2)
    score_max = sum(m.weight for m in metrics)
    health_percent = round((score_total_good / score_max) * 100, 1) if score_max else 0.0
    risk_percent = round(100.0 - health_percent, 1)
    risk_label, risk_display, risk_rank = risk_tuple_from_percent(risk_percent)

    # Highlights
    highlights = []
    # recency highlight based on evaluated target
    if exact_version:
        vdt = release_date_for_version(meta, exact_version)
        if vdt and (dt.datetime.now(dt.timezone.utc) - vdt).days <= 120:
            highlights.append(f"{name}=={exact_version} released in the last 4 months.")
    else:
        latest_dt = parse_latest_release_date(meta)
        if latest_dt and (dt.datetime.now(dt.timezone.utc) - latest_dt).days <= 120:
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

    evaluated_version = exact_version or info.get("version")

    return {
        "package": name,
        "requested": {"raw": None, "exact_version": exact_version} if exact_version else {"raw": None, "exact_version": None},
        "collected_at": dt.datetime.utcnow().isoformat() + "Z",
        "score_total_good": score_total_good,
        "score_max": score_max,
        "health_percent": health_percent,
        "risk_percent": risk_percent,
        "score_percent": risk_percent,
        "risk_level": risk_label,
        "risk_level_display": risk_display,
        "risk_level_rank": risk_rank,
        "info": {
            "name": info.get("name"),
            "summary": info.get("summary"),
            "version_latest": info.get("version"),
            "evaluated_version": evaluated_version,
            "home_page": info.get("home_page"),
            "project_urls": info.get("project_urls"),
        },
        "metrics": [asdict(m) for m in metrics],
        "highlights": highlights,
    }

# ---------- I/O ----------

def print_tldr(results: List[Dict[str, Any]], fail_above: Optional[float], fail_below: Optional[float]) -> None:
    print("\n=== PyPI Audit TL;DR (Inverted: lower is better) ===")
    if fail_above is not None:
        print(f"Quality gate A: FAIL if RISK % > {fail_above}")
    if fail_below is not None:
        print(f"Quality gate B (legacy): FAIL if HEALTH % < {fail_below}")
    if fail_above is not None or fail_below is not None:
        print()
    for r in results:
        name = r.get("package")
        info = r.get("info") or {}
        evaluated_version = (info or {}).get("evaluated_version") or "unknown"
        if "error" in r:
            print(f"[ERROR] - {name}: {r['error']}\n")
            continue
        risk_display = r.get("risk_level_display", "[UNKNOWN]")
        risk_percent = r.get("risk_percent")
        health_percent = r.get("health_percent")
        total_good = r.get("score_total_good")
        smax = r.get("score_max")
        print(f"{risk_display} {name} @ {evaluated_version}: RISK {risk_percent}% (Health {health_percent}%)  GoodPoints {total_good}/{smax}")
        for m in r.get("metrics", []):
            print(f"    • {m['name']}: {m['score']}/{m['weight']} – {m['comment']}")
        highs = r.get("highlights") or []
        if highs:
            print("    Highlights: " + " | ".join(highs))
        print()

def default_out_path(pkgs: List[str]) -> str:
    if len(pkgs) == 1:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", pkgs[0])
        return f"{safe}_pypi_audit.json"
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"pypi_audit_{ts}.json"

def write_json_file(path: str, payload: Any, pretty: bool) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            else:
                json.dump(payload, f, ensure_ascii=False)
    except OSError as e:
        print(f"ERROR: failed to write JSON to '{path}': {e}", file=sys.stderr)
        sys.exit(1)

def read_packages_from_file(path: str) -> List[str]:
    """Read a file and return package specs split by newline, spaces, or commas."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(f"ERROR: failed to read package file '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    parts = re.split(r"[\s,]+", text.strip())
    return [p for p in parts if p]

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Audit PyPI packages for trust & risk signals (inverted scoring).")
    parser.add_argument("packages", nargs="*", help="One or more PyPI package names (optional specifiers, e.g., name==1.2.3).")
    parser.add_argument("--file", type=str, help="Read package names from a file (newline/space/comma-separated).")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON (file and --stdout-json).")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15).")
    parser.add_argument("--no-osv", action="store_true", help="Skip OSV vulnerability check.")

    # Gates:
    parser.add_argument("--fail-above", type=float, default=None,
                        help="Fail (exit 2) if any RISK percent is above this threshold (0-100).")
    parser.add_argument("--fail-below", type=float, default=None,
                        help="[LEGACY] Fail (exit 2) if any HEALTH percent is below this threshold (0-100).")

    parser.add_argument("--out", type=str, default=None, help="Path to write JSON report. Default depends on package count.")
    parser.add_argument("--no-tldr", action="store_true", help="Do not print the TL;DR breakdown.")
    parser.add_argument("--stdout-json", action="store_true", help="Also print the JSON payload to stdout.")
    args = parser.parse_args()

    # Build package list from CLI + optional file
    raw_specs: List[str] = list(args.packages) if args.packages else []
    if args.file:
        raw_specs.extend(read_packages_from_file(args.file))

    if not raw_specs:
        print("No packages specified. Provide package names or use --file <path>.", file=sys.stderr)
        sys.exit(1)

    # Parse specs into (name, exact_version_or_None)
    to_audit: List[Tuple[str, Optional[str], str]] = []  # (name, exact_ver, original_spec)
    for spec in raw_specs:
        name, exact_ver = parse_name_and_exact_version(spec)
        to_audit.append((name, exact_ver, spec))

    # Validate thresholds
    def valid_pct(x):
        return x is None or (0 <= x <= 100)
    if not valid_pct(args.fail_above) or not valid_pct(args.fail_below):
        print("Thresholds must be between 0 and 100.", file=sys.stderr)
        sys.exit(1)
    if args.fail_below is not None and args.fail_above is None:
        print("NOTE: --fail-below applies to HEALTH percent (higher is better). "
              "Prefer --fail-above, which applies to RISK percent (higher is worse).", file=sys.stderr)

    sess = make_session(timeout=args.timeout)
    results: List[Dict[str, Any]] = []
    had_operational_error = False
    gate_failed = False

    for name, exact_ver, original in to_audit:
        meta = fetch_pypi_metadata(sess, name)
        if not meta:
            results.append({
                "package": name,
                "requested": {"raw": original, "exact_version": exact_ver},
                "collected_at": dt.datetime.utcnow().isoformat() + "Z",
                "error": "Package not found or PyPI unreachable."
            })
            had_operational_error = True
            continue

        # If an exact version was requested but is not in releases, return a specific error.
        if exact_ver and exact_ver not in (meta.get("releases") or {}):
            results.append({
                "package": name,
                "requested": {"raw": original, "exact_version": exact_ver},
                "collected_at": dt.datetime.utcnow().isoformat() + "Z",
                "error": f"Version '{exact_ver}' not found for package '{name}'."
            })
            had_operational_error = True
            continue

        scored = score_one(meta, include_osv=not args.no_osv, sess=sess, name=name, exact_version=exact_ver)
        # attach the original spec
        if "requested" in scored:
            scored["requested"]["raw"] = original
        else:
            scored["requested"] = {"raw": original, "exact_version": exact_ver}
        results.append(scored)

    # Apply gates (prefer fail-above if present)
    if not had_operational_error:
        if args.fail_above is not None:
            for r in results:
                rp = r.get("risk_percent")
                if rp is None or rp > args.fail_above:
                    gate_failed = True
                    break
        elif args.fail_below is not None:
            for r in results:
                hp = r.get("health_percent")
                if hp is None or hp < args.fail_below:
                    gate_failed = True
                    break

    # Write JSON report
    out_path = args.out or default_out_path([s for s in (spec for _, _, spec in to_audit)])
    payload = results if len(results) > 1 else results[0]
    write_json_file(out_path, payload, pretty=args.pretty)

    # Optional echo of JSON
    if args.stdout_json:
        if args.pretty:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(payload, ensure_ascii=False))

    # TL;DR
    if not args.no_tldr:
        print_tldr(results, args.fail_above, args.fail_below)
        print(f"JSON report written to: {os.path.abspath(out_path)}")

    # Exit codes
    if had_operational_error:
        sys.exit(1)
    if gate_failed:
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
