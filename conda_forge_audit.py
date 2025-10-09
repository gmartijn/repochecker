#!/usr/bin/env python3
# conda_forge_audit.py — Conda-Forge package audit (integrated metrics, 4-level risk, explainable)
"""
Audits packages from Conda-Forge (or another Anaconda.org channel).
Pulls metadata & download stats from the Anaconda API, optionally inspects the
upstream GitHub repository, integrates OSV vulnerability lookups (severity-aware),
and computes an overall risk rating.

Features
- Single package audit or bulk from a file
- JSON and CSV output modes
- 4-level risk: Low, Medium, High, Critical
- --fail-below to non-zero exit if score falls below a threshold (prints a summary of failures)
- --explain to show step-by-step scoring breakdown
- Optional GitHub enrichment (stars, forks, recent activity); set GITHUB_TOKEN env var for higher rate limits
- OSV lookups (package-first by ecosystem/name, fallback to repo URL), severity-aware scoring
- --skipssl to disable TLS verification (for gnarly CI) and NO_SSL_VERIFY=1 env support
- Sensible, deterministic scoring with weights you can override via --weights

Usage examples
  # Quick audit
  ./conda_forge_audit.py --name numpy

  # With JSON output
  ./conda_forge_audit.py -n pandas --json

  # Bulk mode (one package name per line)
  ./conda_forge_audit.py --input packages.txt --csv out.csv

  # Fail CI if below 70 (prints which packages failed)
  ./conda_forge_audit.py -n scikit-learn --fail-below 70

  # Detailed explanation
  ./conda_forge_audit.py -n xarray --explain
"""
import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except Exception:
    Console = None
    Table = None
    Panel = None
    box = None

console = Console() if Console else None
console_err = Console(stderr=True) if Console else None

ANACONDA_API = os.getenv("ANACONDA_API_BASE", "https://api.anaconda.org")
DEFAULT_CHANNEL = os.getenv("ANACONDA_DEFAULT_CHANNEL", "conda-forge")
GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")

# ---------- HTTP utilities ----------
def requests_session(timeout: int = 20, retries: int = 3, backoff: float = 0.5) -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=["GET", "HEAD", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": "conda-forge-audit/1.1"})
    # attach default timeout via wrapper
    original_request = sess.request
    def _request(method, url, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        return original_request(method, url, **kwargs)
    sess.request = _request  # type: ignore[assignment]
    return sess

SESSION = requests_session()

# ---------- Helpers ----------
def parse_iso(dt_str: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def days_since(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    return int((datetime.now(timezone.utc) - dt).total_seconds() // 86400)

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def pretty_print_result(result: Dict[str, Any], explain: bool = False):
    if not Console:
        print(json.dumps(result, indent=2))
        return
    name = result.get("package", {}).get("name") or result.get("query_name") or "unknown"
    score = result.get("scores", {}).get("overall", 0.0)
    rating = result.get("risk", "Unknown")
    channel = result.get("channel", DEFAULT_CHANNEL)

    header = Panel.fit(
        f"[bold]Conda-Forge Package Audit[/bold]\n"
        f"{name}\n"
        f"Channel: {channel}\n"
        f"Risk: [bold]{rating}[/bold]  •  Score: [bold]{score:.1f}/100[/bold]",
        box=box.ROUNDED if box else None,
    )
    console.print(header)

    # Package panel
    pkg = result.get("package", {})
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE if box else None)
    table.add_column("Field", style="dim")
    table.add_column("Value")
    table.add_row("name", pkg.get("name", "-"))
    table.add_row("summary", pkg.get("summary", "-"))
    table.add_row("latest_version", pkg.get("latest_version", "-"))
    table.add_row("license", pkg.get("license", "-"))
    table.add_row("total_downloads", str(result.get("stats", {}).get("total_downloads", 0)))
    table.add_row("latest_upload", pkg.get("latest_upload", "-"))
    console.print(table)

    # GitHub panel
    gh = result.get("github", {})
    if gh:
        gh_table = Table(show_header=True, header_style="bold", box=box.SIMPLE if box else None)
        gh_table.add_column("GitHub", style="dim")
        gh_table.add_column("Value")
        gh_table.add_row("repo", gh.get("repo", "-"))
        gh_table.add_row("stars", str(gh.get("stargazers_count", "-")))
        gh_table.add_row("forks", str(gh.get("forks_count", "-")))
        gh_table.add_row("open_issues", str(gh.get("open_issues_count", "-")))
        gh_table.add_row("pushed_at", gh.get("pushed_at", "-"))
        console.print(gh_table)

    # Scoring panel
    sc = result.get("scores", {})
    sc_table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY if box else None)
    sc_table.add_column("Metric")
    sc_table.add_column("Score (/100)")
    for key in ["vulnerabilities", "freshness", "popularity", "repo_posture", "license"]:
        if key in sc:
            sc_table.add_row(key, f"{sc[key]:.1f}")
    sc_table.add_row("overall", f"{sc.get('overall', 0):.1f}")
    console.print(sc_table)

    # OSV summary (if present)
    vulns = result.get("vulnerabilities") or {}
    if vulns.get("count") not in (None, 0):
        max_cvss = 0
        sevs = vulns.get("severities") or []
        try:
            max_cvss = max([float(x or 0) for x in sevs]) if sevs else 0
        except Exception:
            max_cvss = 0
        ids = vulns.get("ids") or []
        id_str = ", ".join(ids[:5]) + (" ..." if len(ids) > 5 else "")
        ov = Table(show_header=True, header_style="bold", box=box.SIMPLE if box else None)
        ov.add_column("OSV field", style="dim")
        ov.add_column("Value")
        ov.add_row("count", str(vulns.get("count")))
        ov.add_row("max_cvss", str(max_cvss))
        ov.add_row("ids", id_str or "-")
        console.print(ov)

    if explain and result.get("explain", []):
        console.print(Panel.fit("\n".join(result["explain"]), title="Explanation", box=box.SIMPLE if box else None))

# ---------- Core fetchers ----------
def fetch_anaconda_package(channel: str, name: str) -> Optional[Dict[str, Any]]:
    url = f"{ANACONDA_API}/package/{channel}/{name}"
    r = SESSION.get(url, timeout=30)
    if r.status_code != 200:
        return None
    data = r.json()
    files = data.get("files", [])
    latest_upload_dt = None
    total_downloads = 0
    versions_seen = set()
    version_uploads: Dict[str, datetime] = {}
    for f in files:
        total_downloads += safe_int(f.get("downloads", 0), 0)
        v = f.get("version")
        u = parse_iso(f.get("upload_time", "") or f.get("upload_time_iso_8601", ""))
        if v and u:
            version_uploads[v] = max(u, version_uploads.get(v, u))
            latest_upload_dt = max(u, latest_upload_dt) if latest_upload_dt else u
        if v:
            versions_seen.add(v)

    data["latest_upload"] = latest_upload_dt.isoformat() if latest_upload_dt else None
    data["total_downloads"] = total_downloads
    data["versions"] = sorted(versions_seen)
    data["version_latest_uploads"] = {k: v.isoformat() for k, v in version_uploads.items()}
    return data

def guess_repo_url_from_meta(data: Dict[str, Any]) -> Optional[str]:
    candidates = []
    for key in ("dev_url", "home"):
        val = data.get(key) or (data.get("latest_release") or {}).get(key)
        if val:
            candidates.append(val)
    for key in ("summary", "description"):
        val = data.get(key) or (data.get("latest_release") or {}).get(key)
        if isinstance(val, str):
            urls = re.findall(r"https?://[^\s)]+", val)
            candidates.extend(urls)
    for c in candidates:
        if "github.com" in c:
            return c.strip().rstrip("/")
    return candidates[0].strip().rstrip("/") if candidates else None

def normalize_github_repo(url: str) -> Optional[str]:
    if not url:
        return None
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#]+)", url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2).replace(".git", "")
    return f"{owner}/{repo}"

def fetch_github_repo(repo: str) -> Optional[Dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GITHUB_API_BASE}/repos/{repo}"
    r = SESSION.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        return None
    data = r.json()
    return {
        "repo": repo,
        "stargazers_count": data.get("stargazers_count"),
        "forks_count": data.get("forks_count"),
        "open_issues_count": data.get("open_issues_count"),
        "pushed_at": data.get("pushed_at"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "owner_type": (data.get("owner") or {}).get("type"),
        "archived": data.get("archived"),
        "disabled": data.get("disabled"),
    }

# ---------- OSV integration ----------
def fetch_osv_vulnerabilities(package_name: Optional[str], ecosystem: Optional[str], repo_url: Optional[str]) -> Dict[str, Any]:
    """
    Query OSV for vulnerabilities. Strategy:
    1) If package_name and ecosystem provided (e.g., PyPI), query by package.
    2) Else, if repo_url is known (GitHub), query by repository URL as "repo".
    Returns {count:int|None, ids:list[str], severities:list[float]} where severities are the
    highest numeric severity per vuln (e.g., CVSS base score).
    """
    def _extract_max_severity(vuln: dict) -> float:
        sev_list = vuln.get("severity") or []
        scores = []
        for s in sev_list:
            val = s.get("score")
            try:
                scores.append(float(val))
            except Exception:
                m = (str(val) or "").upper()
                if m == "CRITICAL": scores.append(9.5)
                elif m == "HIGH": scores.append(8.0)
                elif m == "MEDIUM": scores.append(5.5)
                elif m == "LOW": scores.append(2.5)
        return max(scores) if scores else 0.0

    def _query(payload: dict):
        try:
            url = "https://api.osv.dev/v1/query"
            headers = {"Content-Type": "application/json"}
            r = SESSION.post(url, headers=headers, json=payload, timeout=30)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulns") or []
                ids = []
                severities = []
                for v in vulns:
                    vid = v.get("id")
                    if vid:
                        ids.append(vid)
                    severities.append(_extract_max_severity(v))
                return {"count": len(ids), "ids": ids, "severities": severities}
        except Exception:
            pass
        return None

    if package_name and ecosystem:
        res = _query({"package": {"name": package_name, "ecosystem": ecosystem}})
        if res is not None:
            return res

    if repo_url:
        res = _query({"repo": repo_url})
        if res is not None:
            return res

    return {"count": None, "ids": [], "severities": []}

# ---------- Scoring ----------
DEFAULT_WEIGHTS = {
    "vulnerabilities": 0.30,
    "freshness": 0.20,
    "popularity": 0.20,
    "repo_posture": 0.20,
    "license": 0.10,
}

def score_license(license_str: Optional[str]) -> float:
    if not license_str:
        return 50.0
    s = license_str.lower()
    permissive = ["mit", "bsd", "apache", "isc", "zlib", "mpl"]
    restrictive = ["gpl-3", "agpl", "lgpl", "epl", "cdla"]
    if any(p in s for p in permissive):
        return 90.0
    if any(r in s for r in restrictive):
        return 70.0
    if "proprietary" in s or "unknown" in s:
        return 40.0
    return 70.0

def score_freshness(latest_upload_iso: Optional[str]) -> float:
    if not latest_upload_iso:
        return 50.0
    dt = parse_iso(latest_upload_iso)
    if not dt:
        return 50.0
    d = days_since(dt)
    if d is None:
        return 50.0
    if d <= 30:
        return 100.0
    if d >= 365:
        return 20.0
    span = 365 - 30
    val = 100 - ((d - 30) * (80 / span))
    return max(20.0, min(100.0, val))

def score_popularity(total_downloads: int) -> float:
    if total_downloads <= 0:
        return 10.0
    if total_downloads < 1_000:
        return 30.0
    if total_downloads < 10_000:
        return 50.0
    if total_downloads < 100_000:
        return 70.0
    if total_downloads < 1_000_000:
        return 85.0
    return 95.0

def score_repo_posture(gh: Optional[Dict[str, Any]]) -> float:
    if not gh:
        return 60.0
    score = 60.0
    stars = gh.get("stargazers_count") or 0
    forks = gh.get("forks_count") or 0
    open_issues = gh.get("open_issues_count") or 0
    pushed_at = parse_iso(gh.get("pushed_at") or "")
    archived = gh.get("archived")
    disabled = gh.get("disabled")

    if stars > 500: score += 15
    elif stars > 100: score += 10
    elif stars > 20: score += 5

    if forks > 50: score += 10
    elif forks > 10: score += 5

    if open_issues > 500: score -= 15
    elif open_issues > 100: score -= 8
    elif open_issues > 20: score -= 3

    if pushed_at:
        d = days_since(pushed_at) or 9999
        if d <= 30: score += 15
        elif d <= 180: score += 8
        elif d <= 365: score += 3
        else: score -= 10
    else:
        score -= 5

    if archived: score -= 25
    if disabled: score -= 25

    return max(0.0, min(100.0, score))

def score_vulnerabilities(count: Optional[int]) -> float:
    if count is None:
        return 100.0
    if count == 0:
        return 100.0
    if count == 1: return 80.0
    if count == 2: return 60.0
    if count <= 5: return 40.0
    return 20.0

def score_vulnerabilities_osv(count: Optional[int], severities: Optional[list]) -> float:
    """
    Severity-aware vulnerability scoring using OSV data.
    Heuristic:
      - Start from a band based on worst CVSS:
          max_cvss >= 9.0 -> base 20
          7.0 <= max_cvss < 9.0 -> base 40
          4.0 <= max_cvss < 7.0 -> base 60
          0.1 <= max_cvss < 4.0 -> base 80
          no vulns -> 100
      - Then subtract a small penalty for multiple vulns: score -= min(30, log1p(count)*10)
    Clamped to [0,100].
    """
    import math
    if count is None:
        return 100.0
    if not severities:
        return score_vulnerabilities(count)

    try:
        max_cvss = max([float(x or 0) for x in severities]) if severities else 0.0
    except Exception:
        max_cvss = 0.0

    if count == 0 or max_cvss == 0.0:
        base = 100.0
    elif max_cvss >= 9.0:
        base = 20.0
    elif max_cvss >= 7.0:
        base = 40.0
    elif max_cvss >= 4.0:
        base = 60.0
    else:
        base = 80.0

    penalty = 0.0 if count <= 1 else min(30.0, math.log1p(count) * 10.0)
    score = base - penalty
    return max(0.0, min(100.0, score))

def compute_overall(scores: Dict[str, float], weights: Dict[str, float]) -> float:
    total = 0.0
    for k, w in weights.items():
        total += scores.get(k, 0.0) * w
    return max(0.0, min(100.0, total))

def risk_from_score(score: float) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"

def parse_weights(arg: Optional[str]) -> Dict[str, float]:
    if not arg:
        return dict(DEFAULT_WEIGHTS)
    out = dict(DEFAULT_WEIGHTS)
    for pair in arg.split(","):
        if "=" not in pair: continue
        k, v = pair.split("=", 1)
        try:
            out[k.strip()] = float(v)
        except Exception:
            pass
    s = sum(out.values())
    if s <= 0:
        return dict(DEFAULT_WEIGHTS)
    for k in out:
        out[k] = out[k] / s
    return out

# ---------- Audit ----------
def audit_package(name: str, channel: str, weights: Dict[str, float], explain: bool = False,
                  osv_enabled: bool = True, osv_ecosystem: str = "PyPI", osv_name: Optional[str] = None) -> Dict[str, Any]:
    expl: List[str] = []
    pkg = fetch_anaconda_package(channel, name)
    if not pkg:
        return {
            "query_name": name,
            "channel": channel,
            "error": f"Package '{name}' not found in channel '{channel}'."
        }

    latest_upload = pkg.get("latest_upload")
    total_downloads = pkg.get("total_downloads", 0)
    license_str = pkg.get("license") or (pkg.get("latest_release") or {}).get("license")

    repo_url = guess_repo_url_from_meta(pkg) or f"https://github.com/conda-forge/{name}-feedstock"
    gh_repo = normalize_github_repo(repo_url)
    gh = fetch_github_repo(gh_repo) if gh_repo else None

    osv = {"count": None, "ids": [], "severities": []}
    if osv_enabled:
        name_for_osv = osv_name or name
        repo_for_osv = f"https://github.com/{gh_repo}" if gh_repo else None
        osv = fetch_osv_vulnerabilities(name_for_osv, osv_ecosystem, repo_for_osv)

    vuln_count = osv.get("count")
    s_vuln = score_vulnerabilities_osv(vuln_count, osv.get("severities"))

    s_fresh = score_freshness(latest_upload)
    s_pop = score_popularity(int(total_downloads or 0))
    s_repo = score_repo_posture(gh)
    s_lic = score_license(license_str)

    if explain:
        max_cvss = 0
        try:
            max_cvss = max(osv.get("severities") or [0])
        except Exception:
            max_cvss = 0
        expl.append(f"vulnerabilities: {vuln_count if vuln_count is not None else 'unknown'} (max CVSS {max_cvss}) -> {s_vuln:.1f}/100")
        expl.append(f"freshness: latest_upload={latest_upload or 'unknown'} -> {s_fresh:.1f}/100")
        expl.append(f"popularity: total_downloads={total_downloads} -> {s_pop:.1f}/100")
        if gh:
            expl.append(f"repo_posture: stars={gh.get('stargazers_count')}, forks={gh.get('forks_count')}, "
                        f"open_issues={gh.get('open_issues_count')}, pushed_at={gh.get('pushed_at')} "
                        f"-> {s_repo:.1f}/100")
        else:
            expl.append("repo_posture: no repo info -> 60.0/100 (neutral)")
        expl.append(f"license: {license_str or 'unknown'} -> {s_lic:.1f}/100")
        if vuln_count is None:
            expl.append("vulnerabilities source: OSV (no match found or query error)")
        else:
            expl.append(f"vulnerabilities source: OSV -> {vuln_count} findings")

    scores = {
        "vulnerabilities": s_vuln,
        "freshness": s_fresh,
        "popularity": s_pop,
        "repo_posture": s_repo,
        "license": s_lic,
    }
    overall = compute_overall(scores, weights)
    risk = risk_from_score(overall)

    result = {
        "query_name": name,
        "channel": channel,
        "package": {
            "name": pkg.get("name"),
            "summary": pkg.get("summary"),
            "latest_version": pkg.get("latest_version"),
            "license": license_str,
            "latest_upload": latest_upload,
        },
        "stats": {
            "total_downloads": total_downloads,
            "versions": pkg.get("versions", []),
        },
        "github": gh or {},
        "vulnerabilities": {
            "count": vuln_count,
            "source": "OSV" if osv_enabled else "disabled",
            "ids": osv.get("ids"),
            "severities": osv.get("severities"),
        },
        "scores": {
            **scores,
            "overall": overall,
        },
        "risk": risk,
        "weights": weights,
    }
    if explain:
        result["explain"] = expl
    return result

# ---------- CSV ----------
CSV_FIELDS = [
    "name","channel","latest_version","license","latest_upload","total_downloads",
    "gh_repo","gh_stars","gh_forks","gh_open_issues","gh_pushed_at",
    "osv_count","osv_max_cvss",
    "score_vulnerabilities","score_freshness","score_popularity","score_repo_posture","score_license",
    "overall","risk"
]

def write_csv_row(writer, audit: Dict[str, Any]):
    pkg = audit.get("package", {})
    gh = audit.get("github", {})
    sc = audit.get("scores", {})
    vul = audit.get("vulnerabilities") or {}
    sevs = vul.get("severities") or []
    try:
        osv_max = max([float(x or 0) for x in sevs]) if sevs else None
    except Exception:
        osv_max = None
    row = {
        "name": pkg.get("name") or audit.get("query_name"),
        "channel": audit.get("channel"),
        "latest_version": pkg.get("latest_version"),
        "license": pkg.get("license"),
        "latest_upload": pkg.get("latest_upload"),
        "total_downloads": (audit.get("stats") or {}).get("total_downloads"),
        "gh_repo": gh.get("repo"),
        "gh_stars": gh.get("stargazers_count"),
        "gh_forks": gh.get("forks_count"),
        "gh_open_issues": gh.get("open_issues_count"),
        "gh_pushed_at": gh.get("pushed_at"),
        "osv_count": vul.get("count"),
        "osv_max_cvss": osv_max,
        "score_vulnerabilities": sc.get("vulnerabilities"),
        "score_freshness": sc.get("freshness"),
        "score_popularity": sc.get("popularity"),
        "score_repo_posture": sc.get("repo_posture"),
        "score_license": sc.get("license"),
        "overall": sc.get("overall"),
        "risk": audit.get("risk"),
    }
    writer.writerow(row)

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Conda-Forge package auditor")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-n","--name", help="Package name to audit")
    g.add_argument("-i","--input", help="Path to file with package names (one per line)")

    parser.add_argument("-c","--channel", default=DEFAULT_CHANNEL, help=f"Anaconda channel (default: {DEFAULT_CHANNEL})")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--csv", metavar="PATH", help="Write CSV to PATH (bulk or single)")
    parser.add_argument("--weights", help="Override weights, e.g. 'freshness=0.4,popularity=0.2,repo_posture=0.2,license=0.2' (will be normalized)")
    parser.add_argument("--fail-below", type=float, help="Exit non-zero if overall score is below this threshold")
    parser.add_argument("--explain", action="store_true", help="Show step-by-step explanation for the score")
    parser.add_argument("--no-osv", action="store_true", help="Disable OSV vulnerability lookup")
    parser.add_argument("--osv-ecosystem", default=os.environ.get("OSV_ECOSYSTEM_DEFAULT", "PyPI"), help="OSV ecosystem to use for package lookup (default: PyPI)")
    parser.add_argument("--osv-name", help="Override package name used for OSV lookup (default: same as package name)")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL verification for HTTP requests (insecure)")

    args = parser.parse_args()
    weights = parse_weights(args.weights)

    # Handle --skipssl or NO_SSL_VERIFY env early
    if args.skipssl or os.getenv("NO_SSL_VERIFY") == "1":
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            SESSION.verify = False  # type: ignore[attr-defined]
        except Exception:
            pass

    results: List[Dict[str, Any]] = []
    names: List[str] = []

    if args.name:
        names = [args.name.strip()]
    else:
        with open(args.input, "r", encoding="utf-8") as f:
            names = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    for nm in names:
        res = audit_package(
            nm, args.channel, weights, explain=args.explain,
            osv_enabled=(not args.no_osv),
            osv_ecosystem=args.osv_ecosystem,
            osv_name=(args.osv_name or nm)
        )
        results.append(res)

    # Output
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for r in results:
                write_csv_row(writer, r)

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for r in results:
            if "error" in r:
                msg = r["error"]
                if console_err:
                    console_err.print(f"[red]{msg}[/red]")
                else:
                    print(f"ERROR: {msg}", file=sys.stderr)
                continue
            pretty_print_result(r, explain=args.explain)

    # Exit code and message if any fail-below breached
    if args.fail_below is not None:
        failed = []
        for r in results:
            score = (r.get("scores") or {}).get("overall")
            if score is None:
                continue
            if score < args.fail_below:
                nm = (r.get("package") or {}).get("name") or r.get("query_name") or "unknown"
                failed.append((nm, score))
        if failed:
            lines = [f"{len(failed)} package(s) scored below threshold {args.fail_below:.1f}:"]
            for n, s in failed:
                lines.append(f" - {n}: {s:.1f}")
            msg = "\n".join(lines)
            if console_err and Panel:
                try:
                    console_err.print(Panel.fit(msg, title="Fail-below threshold", box=box.SIMPLE if box else None))
                except Exception:
                    print(msg, file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)

if __name__ == "__main__":
    if os.getenv("NO_SSL_VERIFY") == "1":
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        SESSION.verify = False  # type: ignore[attr-defined]
    main()
