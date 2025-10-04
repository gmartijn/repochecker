#!/usr/bin/env python3
"""
NuGet/C# package security audit (enhanced, v1.3)

What it does:
- Queries OSV.dev for known vulnerabilities (ecosystem=NuGet).
- Pulls NuGet metadata (downloads, latest publish, license, repo URL) with robust registration hydration.
- Optionally augments with GitHub repo signals (stars, recent push, archived/disabled).
- Computes a weighted risk score across five core dimensions (vulns, freshness, popularity, repo posture, license)
  and an optional sixth dimension for historical vulns (parameterized weight).
- Generates a PDF report with a summary page, a bar chart (labels won't clip), and a vulnerability table.
- Nice CLI: subcommands (package/lockfile), --no-github, --osv-only, --historical, --history-weight,
  --skipssl (for proxies), and --fail-below (CI-friendly threshold with exit code 3).

Quick examples:
  # JSON only (latest version)
  python nuget-audit.py package --name Newtonsoft.Json --json

  # Specific version + PDF
  python nuget-audit.py package --name Serilog --version 3.0.1 --pdf serilog_audit.pdf

  # Lockfile triage (JSON), fail build if any score < 70
  python nuget-audit.py lockfile --path ./packages.lock.json --json --fail-below 70
"""

import os
import re
import sys
import json
import math
import time
import argparse
import datetime as dt
from typing import Optional, Dict, Any, List, Tuple, Iterable
import textwrap

try:
    import urllib3
except Exception:
    urllib3 = None

try:
    import requests
except Exception:
    print("Please: pip install requests", file=sys.stderr)
    raise

# Optional plotting for PDF
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
except Exception:
    plt = None
    PdfPages = None

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

NUGET_SEARCH = "https://api-v2v3search-0.nuget.org/query"
NUGET_REG_BASE = "https://api.nuget.org/v3/registration5-gz-semver2"
OSV_QUERY = "https://api.osv.dev/v1/query"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "nuget-security-audit/1.3",
    "Accept": "application/json",
})
DEFAULT_TIMEOUT = 20


# ------------------------ HTTP helpers with backoff ------------------------ #
def _get(url: str, *, params=None, headers=None, timeout=DEFAULT_TIMEOUT) -> Optional[dict]:
    last_exception = None
    for attempt in range(3):
        try:
            r = SESSION.get(url, params=params, headers=headers, timeout=timeout)
            if r.status_code in (429, 503):
                ra = r.headers.get("Retry-After")
                try:
                    delay = float(ra) if ra and str(ra).isdigit() else (1.5 * (attempt + 1))
                except Exception:
                    delay = 1.5 * (attempt + 1)
                time.sleep(delay)
                continue
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return None
        except requests.HTTPError as e:
            last_exception = e
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(1.2 * (attempt + 1))
                continue
            return None
        except Exception as e:
            last_exception = e
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None
    if last_exception:
        return None
    return None


def _post(url: str, *, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT) -> Optional[dict]:
    last_exception = None
    for attempt in range(3):
        try:
            r = SESSION.post(url, json=json_body, headers=headers, timeout=timeout)
            if r.status_code in (429, 503):
                ra = r.headers.get("Retry-After")
                try:
                    delay = float(ra) if ra and str(ra).isdigit() else (1.5 * (attempt + 1))
                except Exception:
                    delay = 1.5 * (attempt + 1)
                time.sleep(delay)
                continue
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as e:
            last_exception = e
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(1.2 * (attempt + 1))
                continue
            return None
        except Exception as e:
            last_exception = e
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None
    if last_exception:
        return None
    return None


# ------------------------ OSV ------------------------ #
def query_osv_vulns(package: str, version: Optional[str] = None) -> List[dict]:
    body = {"package": {"name": package, "ecosystem": "NuGet"}}
    if version:
        body["version"] = version
    data = _post(OSV_QUERY, json_body=body) or {}
    vulns = data.get("vulns") or []
    # Normalize severity
    for v in vulns:
        v["_max_cvss"] = _max_cvss(v)
        v["_sev_label"] = _sev_label(v)
    return vulns


def _max_cvss(v: dict) -> Optional[float]:
    scores = []
    for s in v.get("severity") or []:
        try:
            if (s.get("type") or "").upper() in ("CVSS_V3", "CVSS_V3.1", "CVSS_V4"):
                scores.append(float(s.get("score")))
        except Exception:
            pass
    if not scores:
        try:
            ds = v.get("database_specific") or {}
            score = ds.get("severity") or ds.get("cvss") or None
            if isinstance(score, (int, float)):
                scores.append(float(score))
        except Exception:
            pass
    return max(scores) if scores else None


def _sev_label(v: dict) -> str:
    sc = _max_cvss(v)
    if sc is None:
        return (v.get("database_specific") or {}).get("severity") or "UNKNOWN"
    if sc >= 9.0:
        return "CRITICAL"
    if sc >= 7.0:
        return "HIGH"
    if sc >= 4.0:
        return "MEDIUM"
    return "LOW"


# ------------------------ NuGet ------------------------ #
def get_nuget_search(package: str) -> Optional[dict]:
    data = _get(NUGET_SEARCH, params={"q": f"packageid:{package}", "prerelease": "false"})
    if not data:
        return None
    items = data.get("data") or []
    for d in items:
        if (d.get("id") or "").lower() == package.lower():
            return d
    return items[0] if items else None


def get_nuget_registration(package: str) -> Optional[dict]:
    pkg = package.lower()
    return _get(f"{NUGET_REG_BASE}/{pkg}/index.json")


def _semver_key(v: str):
    parts = re.split(r"[.+-]", v)
    try:
        return tuple(int(x) if re.fullmatch(r"\d+", x) else x for x in parts)
    except Exception:
        return tuple(parts)


def _iter_reg_items(reg: dict) -> Iterable[dict]:
    for page in (reg or {}).get("items", []) or []:
        items = page.get("items")
        if not items and page.get("@id"):
            hydrated = _get(page["@id"]) or {}
            items = hydrated.get("items") or []
        for e in items or []:
            yield (e.get("catalogEntry") or {})


def _latest_version_from_reg(reg: dict) -> Optional[str]:
    try:
        versions = [ce.get("version") for ce in _iter_reg_items(reg) if ce.get("version")]
        versions.sort(key=_semver_key)
        return versions[-1] if versions else None
    except Exception:
        return None


def _published_of_version(reg: dict, version: str) -> Optional[str]:
    try:
        for ce in _iter_reg_items(reg):
            if str(ce.get("version")).lower() == str(version).lower():
                return ce.get("published")
    except Exception:
        pass
    return None


def _latest_published_from_reg(reg: dict) -> Optional[str]:
    try:
        last_date = None
        for ce in _iter_reg_items(reg):
            pub = ce.get("published")
            if pub:
                dtv = _try_parse_iso(pub)
                if dtv and (last_date is None or dtv > last_date):
                    last_date = dtv
        return last_date.isoformat() if last_date else None
    except Exception:
        return None


def extract_repo_url_from_docs(search_doc: dict, reg_doc: dict) -> Optional[str]:
    # Prefer repository info from registration pages
    try:
        for ce in _iter_reg_items(reg_doc):
            repo = None
            if isinstance(ce.get("repository"), dict):
                repo = (ce["repository"] or {}).get("url")
            repo = repo or ce.get("repositoryUrl") or ce.get("projectUrl")
            if repo:
                m = re.search(r"https?://github\.com/([^/\s]+)/([^/\s#]+)", repo)
                return f"https://github.com/{m.group(1)}/{m.group(2)}" if m else repo
    except Exception:
        pass
    # Fallback to search doc
    repo = (search_doc or {}).get("repositoryUrl") or (search_doc or {}).get("projectUrl")
    if repo:
        m = re.search(r"https?://github\.com/([^/\s]+)/([^/\s#]+)", repo)
        return f"https://github.com/{m.group(1)}/{m.group(2)}" if m else repo
    return None


# ------------------------ GitHub ------------------------ #
def get_github_repo_stats(repo_url: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"repo_url": repo_url}
    m = re.search(r"github\.com/([^/]+)/([^/#]+)", repo_url or "")
    if not m:
        return out
    owner, repo = m.group(1), m.group(2)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nuget-security-audit/1.3",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    meta = _get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers) or {}
    out.update({
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "open_issues": meta.get("open_issues_count"),
        "pushed_at": meta.get("pushed_at"),
        "archived": meta.get("archived"),
        "disabled": meta.get("disabled"),
        "license": (meta.get("license") or {}).get("spdx_id"),
    })
    return out


# ------------------------ Summarization ------------------------ #
def summarize_nuget(package: str, version: Optional[str]) -> Dict[str, Any]:
    search = get_nuget_search(package) or {}
    reg = get_nuget_registration(package) or {}
    latest_version = search.get("version") or _latest_version_from_reg(reg)
    version_eff = version or latest_version

    total_downloads = search.get("totalDownloads")
    license_expression = search.get("licenseExpression") or search.get("license") or None
    project_url = search.get("projectUrl")
    repo_url = extract_repo_url_from_docs(search, reg)
    published_iso = None
    if version_eff:
        published_iso = _published_of_version(reg, version_eff)
    if not published_iso:
        published_iso = _latest_published_from_reg(reg)

    return {
        "package": package,
        "requested_version": version,
        "effective_version": version_eff,
        "latest_version": latest_version,
        "total_downloads": total_downloads,
        "license_expression": license_expression,
        "project_url": project_url,
        "repo_url": repo_url,
        "published": published_iso,
        "nuget_search": search,
        "nuget_registration": reg,
    }


# ------------------------ Scoring ------------------------ #
def _try_parse_iso(s: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def days_since(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    d = _try_parse_iso(iso)
    if not d:
        return None
    return max(0, (dt.datetime.now(dt.timezone.utc) - d).days)


def _popularity_score(downloads: int) -> float:
    if not downloads or downloads <= 0:
        return 0.0
    lg = max(0.0, math.log10(downloads))
    # Map 1e3 -> 0, 1e7 -> 100
    return max(0.0, min(100.0, (lg - 3.0) / (7.0 - 3.0) * 100.0))


def compute_risk(nuget_info: dict, vulns: List[dict], gh: Dict[str, Any],
                 *, history_count: Optional[int] = None, history_weight: float = 0.0) -> Tuple[Dict[str, float], float, str]:
    scores: Dict[str, float] = {}

    # Vulnerabilities (current version)
    vulns_count = len(vulns)
    max_cvss = max([v.get("_max_cvss") or 0 for v in vulns], default=0)
    vul_score = 100.0
    if vulns_count > 0:
        vul_score -= min(70.0, 15.0 * vulns_count)
        if max_cvss >= 9.0:
            vul_score -= 20
        elif max_cvss >= 7.0:
            vul_score -= 12
        elif max_cvss >= 4.0:
            vul_score -= 6
    scores["vulnerabilities"] = max(0.0, min(100.0, vul_score))

    # Freshness
    d = days_since(nuget_info.get("published"))
    fresh = 100.0
    if d is None:
        fresh -= 15
    elif d <= 30:
        pass
    elif d <= 90:
        fresh -= 10
    elif d <= 180:
        fresh -= 20
    elif d <= 365:
        fresh -= 35
    else:
        fresh -= 55
    scores["freshness"] = max(0.0, min(100.0, fresh))

    # Popularity
    dl = nuget_info.get("total_downloads") or 0
    scores["popularity"] = _popularity_score(dl)

    # Repo posture
    repo = 100.0
    if not nuget_info.get("repo_url"):
        repo -= 15
    if gh.get("archived") or gh.get("disabled"):
        repo -= 40
    stars = gh.get("stars") or 0
    if stars < 10:
        repo -= 10
    elif stars < 100:
        repo -= 5
    if not gh.get("pushed_at"):
        repo -= 10
    else:
        pdays = days_since(gh.get("pushed_at"))
        if pdays is not None:
            if pdays > 365:
                repo -= 25
            elif pdays > 180:
                repo -= 15
            elif pdays > 90:
                repo -= 8
    scores["repo_posture"] = max(0.0, min(100.0, repo))

    # License
    lic = (nuget_info.get("license_expression") or gh.get("license") or "").upper()
    lic_score = 100.0
    if not lic:
        lic_score -= 20
    elif any(x in lic for x in ("GPL", "AGPL")):
        lic_score -= 10
    elif any(x in lic for x in ("LGPL", "MPL")):
        lic_score -= 5
    if lic in ("NOASSERTION", "CUSTOM"):
        lic_score -= 15
    scores["license"] = max(0.0, min(100.0, lic_score))

    # Optional historical penalty dimension
    if history_weight and history_weight > 0:
        hc = max(0, int(history_count or 0))
        history_score = max(0.0, 100.0 - min(80.0, 8.0 * hc))  # each past vuln knocks 8 points, cap 80
        scores["history"] = history_score

    # Weighted overall (normalize when history added)
    base_weights = {
        "vulnerabilities": 0.40,
        "freshness": 0.20,
        "popularity": 0.15,
        "repo_posture": 0.15,
        "license": 0.10,
    }
    if "history" in scores:
        base_weights["history"] = max(0.0, float(history_weight))
    total_w = sum(base_weights.values()) or 1.0
    weights = {k: v / total_w for k, v in base_weights.items()}

    overall = round(sum(scores[k] * weights.get(k, 0.0) for k in scores.keys()), 1)
    rating = (
        "low" if overall >= 80 else
        "medium" if overall >= 60 else
        "high" if overall >= 40 else
        "critical"
    )
    return scores, overall, rating


# ------------------------ Reports ------------------------ #
def make_pdf_report(path: str, package: str, version: Optional[str], nuget_info: dict, gh: dict,
                    vulns: List[dict], scores: Dict[str, float], overall: float, rating: str,
                    *, historical_total: Optional[int] = None, historical_past: Optional[int] = None):
    if not (plt and PdfPages):
        raise RuntimeError("matplotlib is required for PDF output. pip install matplotlib")

    rating_colors = {
        "low": "#2ca02c",
        "medium": "#ffbf00",
        "high": "#ff7f0e",
        "critical": "#d62728",
    }

    dims = list(scores.keys())
    values = [scores[k] for k in dims]

    with PdfPages(path) as pdf:
        # Page 1: Summary
        fig1, ax1 = plt.subplots(figsize=(8.5, 11), dpi=150, constrained_layout=True)
        ax1.axis("off")
        lines = []
        lines.append("NuGet Security Audit")
        lines.append(f"Package: {package} ({version or nuget_info.get('effective_version') or 'n/a'})")
        lines.append(f"Latest: {nuget_info.get('latest_version') or 'n/a'}")
        lines.append(f"Downloads: {nuget_info.get('total_downloads') or 'n/a'}")
        lines.append(f"Published: {nuget_info.get('published') or 'n/a'}")
        if nuget_info.get("project_url"):
            lines.append(f"Project: {nuget_info.get('project_url')}")
        if nuget_info.get("repo_url"):
            lines.append(f"Repo: {nuget_info.get('repo_url')}")
        if gh:
            lines.append(f"GitHub stars: {gh.get('stars')}  open_issues: {gh.get('open_issues')}  archived: {bool(gh.get('archived'))}")
        lines.append(f"License: {nuget_info.get('license_expression') or gh.get('license') or 'n/a'}")
        lines.append("")
        if vulns:
            lines.append(f"Vulnerabilities (current): {len(vulns)}  Max CVSS: {max([v.get('_max_cvss') or 0 for v in vulns], default=0):.1f}")
        else:
            lines.append("Vulnerabilities (current): 0")
        if historical_total is not None:
            past_str = f", Past (not affecting audited): {historical_past}" if historical_past is not None else ""
            lines.append(f"Historical vulns (all versions): {historical_total}{past_str}")
        lines.append(f"Overall: {overall}/100  Rating: {rating.upper()}")

        y = 0.95
        ax1.text(0.02, y, lines[0], fontsize=20, fontweight="bold", transform=ax1.transAxes)
        y -= 0.06
        for line in lines[1:]:
            ax1.text(0.02, y, line, fontsize=12, transform=ax1.transAxes)
            y -= 0.035

        ax1.add_patch(matplotlib.patches.Rectangle((0.02, y-0.02), 0.04, 0.02, color=rating_colors.get(rating, "#333"), transform=ax1.transAxes, clip_on=False))
        ax1.text(0.07, y-0.02, f"Rating: {rating.upper()}", fontsize=12, va="bottom", transform=ax1.transAxes)

        pdf.savefig(fig1, bbox_inches="tight")
        plt.close(fig1)

        # Page 2: Scores bar chart
        fig2, ax2 = plt.subplots(figsize=(10.0, 5.0), dpi=150, constrained_layout=True)
        bars = ax2.bar(dims, values)
        ax2.set_ylim(0, 100)
        ax2.set_ylabel("Score (0–100)")
        ax2.set_title(f"Security Dimension Scores — Overall {overall}/100 ({rating})",
                      color=rating_colors.get(rating, "#222"))
        plt.setp(ax2.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")
        for b, v in zip(bars, values):
            ax2.text(b.get_x() + b.get_width()/2, v + 1, f"{int(round(v))}", ha="center", va="bottom", fontsize=9)
        fig2.subplots_adjust(bottom=0.25)
        pdf.savefig(fig2, bbox_inches="tight")
        plt.close(fig2)

        # Page 3: Vulnerabilities (if any)
        if vulns:
            fig3, ax3 = plt.subplots(figsize=(10.0, 8.0), dpi=150, constrained_layout=True)
            ax3.axis("off")
            ax3.set_title("Known Vulnerabilities (OSV.dev)", fontsize=14, fontweight="bold")
            rows = []
            for v in vulns[:20]:
                aliases = v.get("aliases")
                ids = ", ".join(aliases) if isinstance(aliases, list) and aliases else (v.get("id") or "—")
                desc = (v.get("summary") or v.get("details") or "").strip().replace("\n", " ")
                if len(desc) > 140:
                    desc = desc[:137] + "..."
                rows.append([ids, v.get("_sev_label"), f"{v.get('_max_cvss') or '—'}", desc])
            table = ax3.table(cellText=rows, colLabels=["ID", "Severity", "CVSS", "Summary"], loc="center", cellLoc="left")
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.2)
            try:
                for i in range(4):
                    table.auto_set_column_width(col=i)
            except Exception:
                pass
            pdf.savefig(fig3, bbox_inches="tight")
            plt.close(fig3)


# ------------------------ Lockfile helpers ------------------------ #
def parse_packages_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out: List[Tuple[str, Optional[str]]] = []
    deps = data.get("dependencies") or {}
    for _tfm, tfm_deps in (deps.items() if isinstance(deps, dict) else []):
        if not isinstance(tfm_deps, dict):
            continue
        for name, meta in tfm_deps.items():
            ver = None
            if isinstance(meta, dict):
                ver = meta.get("resolved") or meta.get("version")
            out.append((name, ver))
    if not out and isinstance(data.get("packages"), list):
        for p in data["packages"]:
            name = p.get("id") or p.get("name")
            ver = p.get("version")
            if name:
                out.append((name, ver))
    return out


def _discover_lockfile(start_dir: str) -> Optional[str]:
    candidate = os.path.join(start_dir, "packages.lock.json")
    if os.path.isfile(candidate):
        return candidate
    for root, _dirs, files in os.walk(start_dir):
        if "packages.lock.json" in files:
            return os.path.join(root, "packages.lock.json")
    return None


def list_auditable_packages(lock_path: Optional[str]) -> List[Tuple[str, Optional[str]]]:
    path = lock_path or _discover_lockfile(os.getcwd())
    if not path or not os.path.isfile(path):
        print("No packages.lock.json found. Specify --path to a lockfile.", file=sys.stderr)
        return []
    items = parse_packages_lock(path)
    best: Dict[str, Optional[str]] = {}
    for name, ver in items:
        if name not in best or (ver and not best[name]):
            best[name] = ver
    return sorted(best.items(), key=lambda kv: kv[0].lower())


# ------------------------ Orchestration ------------------------ #
def audit_package(package: str, version: Optional[str], pdf_out: Optional[str], json_out: bool, *,
                  no_github: bool = False, osv_only: bool = False, historical: bool = False,
                  history_weight: float = 0.0, fail_below: Optional[float] = None):
    if osv_only:
        if fail_below is not None:
            print("--fail-below cannot be used with --osv-only (no overall score is computed).", file=sys.stderr)
            sys.exit(2)
        current_vulns = query_osv_vulns(package, version)
        all_vulns = query_osv_vulns(package) if historical else []
        result = {
            "package": package,
            "requested_version": version,
            "vulnerabilities": [{"id": v.get("id"), "max_cvss": v.get("_max_cvss"), "severity": v.get("_sev_label")} for v in current_vulns],
            "count": len(current_vulns),
        }
        if historical:
            result["historical_vulnerabilities"] = [{"id": v.get("id"), "max_cvss": v.get("_max_cvss"), "severity": v.get("_sev_label")} for v in all_vulns]
            result["historical_counts"] = {
                "total": len(all_vulns),
                "past_not_affecting_current": max(0, len(all_vulns) - len(current_vulns)),
            }
        print(json.dumps(result, indent=2))
        return

    nuget = summarize_nuget(package, version)
    gh = get_github_repo_stats(nuget.get("repo_url")) if (nuget.get("repo_url") and not no_github) else {}
    vulns = query_osv_vulns(package, nuget.get("effective_version"))
    all_vulns = query_osv_vulns(package) if historical else []
    history_count = len(all_vulns) if historical else None

    scores, overall, rating = compute_risk(nuget, vulns, gh, history_count=history_count, history_weight=history_weight)

    # Attach historical counts (for JSON and PDF)
    hist_total = None
    hist_past = None
    if historical:
        hist_total = len(all_vulns)
        hist_past = max(0, len(all_vulns) - len(vulns))

    result = {
        "package": package,
        "requested_version": version,
        "version": nuget.get("effective_version"),
        "nuget": {
            "latest_version": nuget.get("latest_version"),
            "published": nuget.get("published"),
            "total_downloads": nuget.get("total_downloads"),
            "license_expression": nuget.get("license_expression"),
            "project_url": nuget.get("project_url"),
            "repo_url": nuget.get("repo_url"),
        },
        "github": gh,
        "vulnerabilities": [{"id": v.get("id"), "max_cvss": v.get("_max_cvss"), "severity": v.get("_sev_label")} for v in vulns],
        "osv_counts": {
            "current": len(vulns),
            "historical_total": hist_total,
            "historical_past_not_affecting": hist_past,
        },
        "scores": scores,
        "overall": overall,
        "rating": rating,
    }

    if json_out or not pdf_out:
        print(json.dumps(result, indent=2))

    if pdf_out:
        make_pdf_report(pdf_out, package, version, nuget, gh, vulns, scores, overall, rating,
                        historical_total=hist_total, historical_past=hist_past)
        print(f"PDF written: {pdf_out}")

    # Enforce --fail-below threshold
    if fail_below is not None:
        try:
            thr = float(fail_below)
        except Exception:
            print("Invalid --fail-below value; must be a number between 0 and 100.", file=sys.stderr)
            sys.exit(2)
        if not (0.0 <= thr <= 100.0):
            print("Invalid --fail-below value; must be within 0..100.", file=sys.stderr)
            sys.exit(2)
        if overall < thr:
            print(f"FAIL-BELOW: overall {overall} < threshold {thr}", file=sys.stderr)
            sys.exit(3)


def audit_lockfile(lock_path: str, pdf_out: Optional[str], json_out: bool, *,
                   no_github: bool = False, osv_only: bool = False, historical: bool = False,
                   history_weight: float = 0.0, fail_below: Optional[float] = None):
    # Validate threshold early
    thr = None
    if fail_below is not None:
        try:
            thr = float(fail_below)
        except Exception:
            print("Invalid --fail-below value; must be a number between 0 and 100.", file=sys.stderr)
            sys.exit(2)
        if not (0.0 <= thr <= 100.0):
            print("Invalid --fail-below value; must be within 0..100.", file=sys.stderr)
            sys.exit(2)
        if osv_only:
            print("--fail-below cannot be used with --osv-only (no overall score is computed).", file=sys.stderr)
            sys.exit(2)

    items = parse_packages_lock(lock_path)
    results = []
    for name, ver in items[:50]:  # cap for speed
        if osv_only:
            vulns = query_osv_vulns(name, ver)
            all_vulns = query_osv_vulns(name) if historical else []
            r = {
                "package": name,
                "version": ver,
                "vulnerabilities": len(vulns),
            }
            if historical:
                r["historical_total"] = len(all_vulns)
                r["historical_past_not_affecting"] = max(0, len(all_vulns) - len(vulns))
            results.append(r)
            sys.stderr.write(f"[OSV] {name} {ver or ''} vulns={r['vulnerabilities']}\n")
            continue

        nuget = summarize_nuget(name, ver)
        gh = get_github_repo_stats(nuget.get("repo_url")) if (nuget.get("repo_url") and not no_github) else {}
        vulns = query_osv_vulns(name, nuget.get("effective_version"))
        all_vulns = query_osv_vulns(name) if historical else []
        history_count = len(all_vulns) if historical else None
        scores, overall, rating = compute_risk(nuget, vulns, gh, history_count=history_count, history_weight=history_weight)

        r = {
            "package": name,
            "version": ver or nuget.get("effective_version"),
            "overall": overall,
            "rating": rating,
            "vulnerabilities": len(vulns),
        }
        if historical:
            r["historical_total"] = len(all_vulns)
            r["historical_past_not_affecting"] = max(0, len(all_vulns) - len(vulns))

        results.append(r)
        sys.stderr.write(f"{name} {r['version']} {rating} {overall} vulns={r['vulnerabilities']}\n")

    payload = {"lockfile": lock_path, "results": results}
    if json_out or not pdf_out:
        print(json.dumps(payload, indent=2))

    if pdf_out:
        if not (plt and PdfPages):
            raise RuntimeError("matplotlib is required for PDF output. pip install matplotlib")
        with PdfPages(pdf_out) as pdf:
            fig, ax = plt.subplots(figsize=(10, 8), dpi=150, constrained_layout=True)
            ax.axis("off")
            ax.set_title(f"NuGet Lockfile Audit — {os.path.basename(lock_path)}", fontsize=14, fontweight="bold")
            if results:
                if osv_only:
                    if any('historical_total' in r for r in results):
                        rows = [[r["package"], r.get("version") or "n/a", r["vulnerabilities"], r.get("historical_total",""), r.get("historical_past_not_affecting","")] for r in results]
                        col_labels = ["Package", "Version", "Vulns", "HistVulns", "Past"]
                    else:
                        rows = [[r["package"], r.get("version") or "n/a", r["vulnerabilities"]] for r in results]
                        col_labels = ["Package", "Version", "Vulns"]
                else:
                    if any('historical_total' in r for r in results):
                        rows = [[r["package"], r.get("version") or "n/a", r["rating"], r["overall"], r["vulnerabilities"], r.get("historical_total",""), r.get("historical_past_not_affecting","")] for r in results]
                        col_labels = ["Package", "Version", "Rating", "Score", "Vulns", "HistVulns", "Past"]
                    else:
                        rows = [[r["package"], r.get("version") or "n/a", r["rating"], r["overall"], r["vulnerabilities"]] for r in results]
                        col_labels = ["Package", "Version", "Rating", "Score", "Vulns"]
                table = ax.table(cellText=rows, colLabels=col_labels, loc="center", cellLoc="left")
                table.auto_set_font_size(False)
                table.set_fontsize(9)
                table.scale(1, 1.2)
                try:
                    for i in range(len(col_labels)):
                        table.auto_set_column_width(col=i)
                except Exception:
                    pass
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)
        print(f"PDF written: {pdf_out}")

    # Enforce --fail-below after outputs
    if thr is not None:
        below = [r for r in results if isinstance(r.get("overall"), (int, float)) and r.get("overall") < thr]
        if below:
            names = ", ".join(f"{r['package']}({r['overall']})" for r in below[:10])
            if len(below) > 10:
                names += ", ..."
            print(f"FAIL-BELOW: {len(below)} package(s) below threshold {thr}: {names}", file=sys.stderr)
            sys.exit(3)


# ------------------------ CLI ------------------------ #
def _full_help_message() -> str:
    return textwrap.dedent("""\
    USAGE:
      nuget-audit.py --list [--path PATH] [--skipssl]
      nuget-audit.py package --name NAME [--version VERSION] [--pdf PATH] [--json]
                             [--no-github] [--osv-only] [--historical] [--history-weight FLOAT]
                             [--fail-below FLOAT] [--skipssl]
      nuget-audit.py lockfile --path PATH [--pdf PATH] [--json]
                              [--no-github] [--osv-only] [--historical] [--history-weight FLOAT]
                              [--fail-below FLOAT] [--skipssl]

    GLOBAL OPTIONS:
      --list                   List packages from packages.lock.json that can be audited
      --path PATH              Path to packages.lock.json (for --list or lockfile subcommand)
      --skipssl                Skip SSL certificate verification (useful behind some proxies; not recommended)

    SUBCOMMANDS & OPTIONS:
      package                  Audit a single package
        --name NAME            NuGet package ID (required)
        --version VERSION      Specific version (defaults to latest)
        --pdf PATH             Path to output PDF (if omitted, prints JSON only)
        --json                 Print JSON to stdout
        --no-github            Skip GitHub API calls
        --osv-only             Only query OSV for vulnerabilities and print results
        --historical           Include historical OSV vulnerabilities (all versions) and counts
        --history-weight FLOAT Weight to include historical vuln metric in overall score (default 0.0 = ignore)
        --fail-below FLOAT     Exit with code 3 if overall score is below this threshold (0-100)

      lockfile                 Audit packages.lock.json
        --path PATH            Path to packages.lock.json (required)
        --pdf PATH             Path to output PDF (if omitted, prints JSON only)
        --json                 Print JSON to stdout
        --no-github            Skip GitHub API calls
        --osv-only             Only query OSV for vulnerabilities and print results
        --historical           Include historical OSV vulnerabilities (all versions) and counts
        --history-weight FLOAT Weight to include historical vuln metric in overall score (default 0.0 = ignore)
        --fail-below FLOAT     Exit with code 3 if any package's overall score is below this threshold (0-100)

    ENVIRONMENT:
      GITHUB_TOKEN             GitHub token for higher rate limits when calling GitHub API

    EXIT CODES:
      0  success
      2  usage error / incompatible flags (e.g., --fail-below with --osv-only)
      3  threshold failure (one or more scores fell below --fail-below)

    EXAMPLES:
      python nuget-audit.py --list --path ./packages.lock.json --skipssl
      python nuget-audit.py package --name Serilog --json --skipssl
      python nuget-audit.py package --name Serilog --pdf serilog_audit.pdf
      python nuget-audit.py lockfile --path ./packages.lock.json --osv-only
      python nuget-audit.py package --name Newtonsoft.Json --no-github --json
      python nuget-audit.py package --name Serilog --json --historical --history-weight 0.25
      python nuget-audit.py package --name Serilog --json --fail-below 75.0
      python nuget-audit.py lockfile --path ./packages.lock.json --json --fail-below 70.0
    """)


def main():
    ap = argparse.ArgumentParser(description="Audit security of C# NuGet modules and optionally generate a PDF report.")
    ap.add_argument("--list", action="store_true", help="List packages from packages.lock.json that can be audited")
    ap.add_argument("--path", help="Path to packages.lock.json for --list (defaults to auto-detect)")
    ap.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification (useful behind some proxies; not recommended)")

    sub = ap.add_subparsers(dest="cmd", required=False)

    ap_pkg = sub.add_parser("package", help="Audit a single package")
    ap_pkg.add_argument("--name", required=True, help="NuGet package ID")
    ap_pkg.add_argument("--version", help="Specific version (defaults to latest)")
    ap_pkg.add_argument("--pdf", help="Path to output PDF (if omitted, prints JSON only)")
    ap_pkg.add_argument("--json", action="store_true", help="Print JSON to stdout")
    ap_pkg.add_argument("--no-github", action="store_true", help="Skip GitHub API calls")
    ap_pkg.add_argument("--osv-only", action="store_true", help="Only query OSV for vulnerabilities and print results")
    ap_pkg.add_argument("--historical", action="store_true", help="Include historical OSV vulnerabilities (all versions) and counts")
    ap_pkg.add_argument("--history-weight", type=float, default=0.0, help="Weight to include historical vuln metric in overall score (default 0.0 = ignore)")
    ap_pkg.add_argument("--fail-below", type=float, help="Exit with code 3 if overall score is below this threshold (0-100)")

    ap_lock = sub.add_parser("lockfile", help="Audit packages.lock.json")
    ap_lock.add_argument("--path", required=True, help="Path to packages.lock.json")
    ap_lock.add_argument("--pdf", help="Path to output PDF (if omitted, prints JSON only)")
    ap_lock.add_argument("--json", action="store_true", help="Print JSON to stdout")
    ap_lock.add_argument("--no-github", action="store_true", help="Skip GitHub API calls")
    ap_lock.add_argument("--osv-only", action="store_true", help="Only query OSV for vulnerabilities and print results")
    ap_lock.add_argument("--historical", action="store_true", help="Include historical OSV vulnerabilities (all versions) and counts")
    ap_lock.add_argument("--history-weight", type=float, default=0.0, help="Weight to include historical vuln metric in overall score (default 0.0 = ignore)")
    ap_lock.add_argument("--fail-below", type=float, help="Exit with code 3 if any package's overall score is below this threshold (0-100)")

    args = ap.parse_args()

    # Apply global SSL skip if requested
    if getattr(args, "skipssl", False):
        SESSION.verify = False
        try:
            if urllib3 is not None:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    # Handle --list early
    if getattr(args, "list", False):
        items = list_auditable_packages(getattr(args, "path", None))
        if not items:
            sys.exit(1)
        for name, ver in items:
            print(f"{name}" + (f"=={ver}" if ver else ""))
        return

    # If no subcommand was provided, show help + extended usage
    if not args.cmd:
        ap.print_help()
        print(_full_help_message(), file=sys.stderr)
        sys.exit(2)

    if args.cmd == "package":
        audit_package(args.name, args.version, args.pdf, args.json,
                      no_github=args.no_github, osv_only=args.osv_only,
                      historical=args.historical, history_weight=args.history_weight,
                      fail_below=args.fail_below)
    elif args.cmd == "lockfile":
        audit_lockfile(args.path, args.pdf, args.json,
                       no_github=args.no_github, osv_only=args.osv_only,
                       historical=args.historical, history_weight=args.history_weight,
                       fail_below=args.fail_below)


if __name__ == "__main__":
    main()
