#!/usr/bin/env python3
"""
NuGet/C# package security audit:
- Queries OSV.dev for known vulnerabilities (ecosystem=NuGet).
- Pulls NuGet metadata (downloads, latest publish, license, repo URL).
- Optionally augments with GitHub repo signals (stars, push activity) if a repo URL exists.
- Computes a weighted risk score.
- Generates a PDF report with a summary page and a bar chart (x-axis labels not clipped).
"""

import os
import re
import sys
import json
import math
import time
import argparse
import datetime as dt
from typing import Optional, Dict, Any, List, Tuple

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
    "User-Agent": "nuget-security-audit/1.0",
    "Accept": "application/json",
})
DEFAULT_TIMEOUT = 20


def _get(url: str, *, params=None, headers=None, timeout=DEFAULT_TIMEOUT) -> Optional[dict]:
    try:
        r = SESSION.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code == 429:
            # backoff a little
            time.sleep(1.0)
            r = SESSION.get(url, params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        if "application/json" in (r.headers.get("Content-Type") or ""):
            return r.json()
        try:
            return r.json()
        except Exception:
            return None
    except Exception:
        return None


def _post(url: str, *, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT) -> Optional[dict]:
    try:
        r = SESSION.post(url, json=json_body, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


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
            if s.get("type", "").upper() == "CVSS_V3":
                scores.append(float(s.get("score")))
        except Exception:
            pass
    if not scores:
        # fallback to database_specific if present
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


def get_nuget_search(package: str) -> Optional[dict]:
    data = _get(NUGET_SEARCH, params={"q": f"packageid:{package}", "prerelease": "false"})
    if not data:
        return None
    items = data.get("data") or []
    for d in items:
        # Exact match on id if present
        if d.get("id", "").lower() == package.lower():
            return d
    return items[0] if items else None


def get_nuget_registration(package: str) -> Optional[dict]:
    pkg = package.lower()
    return _get(f"{NUGET_REG_BASE}/{pkg}/index.json")


def extract_repo_url_from_nuget(search_doc: dict) -> Optional[str]:
    if not isinstance(search_doc, dict):
        return None
    # Prefer repository URL if present in registration (source repo)
    repo = search_doc.get("repositoryUrl") or search_doc.get("repository")
    # Fallback to projectUrl
    repo = repo or search_doc.get("projectUrl")
    if not repo:
        return None
    # Look for GitHub repo
    m = re.search(r"https?://github\.com/([^/\s]+)/([^/\s#]+)", repo)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return repo


def get_github_repo_stats(repo_url: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"repo_url": repo_url}
    m = re.search(r"github\.com/([^/]+)/([^/#]+)", repo_url or "")
    if not m:
        return out
    owner, repo = m.group(1), m.group(2)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nuget-security-audit/1.0",
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


def summarize_nuget(package: str, version: Optional[str]) -> Dict[str, Any]:
    search = get_nuget_search(package) or {}
    reg = get_nuget_registration(package) or {}
    latest_version = search.get("version") or _latest_version_from_reg(reg)
    version_eff = version or latest_version

    total_downloads = search.get("totalDownloads")
    license_expression = search.get("licenseExpression") or search.get("license") or None
    project_url = search.get("projectUrl")
    repo_url = extract_repo_url_from_nuget(search)
    published_iso = _latest_published_from_reg(reg)  # fallback if not in search

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


def _latest_version_from_reg(reg: dict) -> Optional[str]:
    try:
        items = reg.get("items") or []
        versions = []
        for page in items:
            for e in page.get("items") or []:
                ci = e.get("catalogEntry") or {}
                versions.append(ci.get("version"))
        versions = [v for v in versions if isinstance(v, str)]
        # naive semver sort by split ints where possible
        def _key(v: str):
            parts = re.split(r"[.+-]", v)
            try:
                return tuple(int(x) if x.isdigit() else x for x in parts)
            except Exception:
                return tuple(parts)
        versions.sort(key=_key)
        return versions[-1] if versions else None
    except Exception:
        return None


def _latest_published_from_reg(reg: dict) -> Optional[str]:
    try:
        items = reg.get("items") or []
        last_date = None
        for page in items:
            for e in page.get("items") or []:
                ci = e.get("catalogEntry") or {}
                pub = ci.get("published")
                if pub:
                    dtv = _try_parse_iso(pub)
                    if dtv and (last_date is None or dtv > last_date):
                        last_date = dtv
        return last_date.isoformat() if last_date else None
    except Exception:
        return None


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


def compute_risk(nuget_info: dict, vulns: List[dict], gh: Dict[str, Any]) -> Tuple[Dict[str, float], float, str]:
    # Dimensions
    # - vulnerabilities (count + max severity)
    # - freshness (days since latest publish)
    # - popularity (downloads)
    # - repo posture (stars, archived flag)
    # - license
    scores: Dict[str, float] = {}

    # Vulnerabilities: start at 100; subtract based on severity and count
    vulns_count = len(vulns)
    max_cvss = max([v.get("_max_cvss") or 0 for v in vulns], default=0)
    vul_score = 100.0
    if vulns_count > 0:
        # Heavier hit for critical/high
        vul_score -= min(70.0, 15.0 * vulns_count)
        if max_cvss >= 9.0:
            vul_score -= 20
        elif max_cvss >= 7.0:
            vul_score -= 12
        elif max_cvss >= 4.0:
            vul_score -= 6
    vul_score = max(0.0, min(100.0, vul_score))
    scores["vulnerabilities"] = vul_score

    # Freshness
    d = days_since(nuget_info.get("published"))
    fresh = 100.0
    if d is None:
        fresh -= 15
    elif d <= 30:
        fresh -= 0
    elif d <= 90:
        fresh -= 10
    elif d <= 180:
        fresh -= 20
    elif d <= 365:
        fresh -= 35
    else:
        fresh -= 55
    fresh = max(0.0, min(100.0, fresh))
    scores["freshness"] = fresh

    # Popularity (downloads)
    dl = nuget_info.get("total_downloads") or 0
    # log-scale mapping to 0..100 with 1e6 ~ 80, 1e7+ ~ 100
    pop = 0.0 if dl <= 0 else min(100.0, 20.0 + 20.0 * math.log10(max(1, dl)))
    pop = max(0.0, min(100.0, pop))
    scores["popularity"] = pop

    # Repo posture
    repo = 100.0
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
    repo = max(0.0, min(100.0, repo))
    scores["repo_posture"] = repo

    # License
    lic = (nuget_info.get("license_expression") or gh.get("license") or "").upper()
    lic_score = 100.0
    if not lic:
        lic_score -= 20
    elif any(x in lic for x in ("GPL", "AGPL")):
        lic_score -= 10  # caution for restrictive copyleft in many enterprise contexts
    scores["license"] = max(0.0, min(100.0, lic_score))

    # Weighted overall
    weights = {
        "vulnerabilities": 0.40,
        "freshness": 0.20,
        "popularity": 0.15,
        "repo_posture": 0.15,
        "license": 0.10,
    }
    overall = round(sum(scores[k] * w for k, w in weights.items()), 1)
    rating = (
        "low" if overall >= 80 else
        "medium" if overall >= 60 else
        "high" if overall >= 40 else
        "critical"
    )
    return scores, overall, rating


def make_pdf_report(path: str, package: str, version: Optional[str], nuget_info: dict, gh: dict, vulns: List[dict], scores: Dict[str, float], overall: float, rating: str):
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
        lines.append(f"NuGet Security Audit")
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
        lines.append(f"Vulnerabilities: {len(vulns)}  Max CVSS: {max([v.get('_max_cvss') or 0 for v in vulns], default=0):.1f}" if vulns else "Vulnerabilities: 0")
        lines.append(f"Overall: {overall}/100  Rating: {rating.upper()}")

        y = 0.95
        ax1.text(0.02, y, lines[0], fontsize=20, fontweight="bold", transform=ax1.transAxes)
        y -= 0.06
        for line in lines[1:]:
            ax1.text(0.02, y, line, fontsize=12, transform=ax1.transAxes)
            y -= 0.035

        # simple legend
        ax1.add_patch(matplotlib.patches.Rectangle((0.02, y-0.02), 0.04, 0.02, color=rating_colors.get(rating, "#333"), transform=ax1.transAxes, clip_on=False))
        ax1.text(0.07, y-0.02, f"Rating: {rating.upper()}", fontsize=12, va="bottom", transform=ax1.transAxes)

        pdf.savefig(fig1, bbox_inches="tight")
        plt.close(fig1)

        # Page 2: Scores bar chart (ensure x labels not clipped)
        fig2, ax2 = plt.subplots(figsize=(10.0, 5.0), dpi=150, constrained_layout=True)
        bars = ax2.bar(dims, values, color="#1f77b4")
        ax2.set_ylim(0, 100)
        ax2.set_ylabel("Score (0–100)")
        ax2.set_title(f"Security Dimension Scores — Overall {overall}/100 ({rating})", color=rating_colors.get(rating, "#222"))
        # Rotate and anchor to avoid clipping
        plt.setp(ax2.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")
        for b, v in zip(bars, values):
            ax2.text(b.get_x() + b.get_width()/2, v + 1, f"{int(round(v))}", ha="center", va="bottom", fontsize=9)
        # Ensure margins are sufficient even if labels are long
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
                ids = ", ".join(v.get("aliases") or v.get("id") or [])
                if not ids:
                    ids = v.get("id") or "—"
                desc = (v.get("summary") or v.get("details") or "").strip().replace("\n", " ")
                if len(desc) > 140:
                    desc = desc[:137] + "..."
                rows.append([ids, v.get("_sev_label"), f"{v.get('_max_cvss') or '—'}", desc])
            table = ax3.table(cellText=rows, colLabels=["ID", "Severity", "CVSS", "Summary"], loc="center", cellLoc="left")
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.2)
            pdf.savefig(fig3, bbox_inches="tight")
            plt.close(fig3)


def audit_package(package: str, version: Optional[str], pdf_out: Optional[str], json_out: bool):
    nuget = summarize_nuget(package, version)
    gh = get_github_repo_stats(nuget.get("repo_url")) if nuget.get("repo_url") else {}
    vulns = query_osv_vulns(package, nuget.get("effective_version"))
    scores, overall, rating = compute_risk(nuget, vulns, gh)

    result = {
        "package": package,
        "version": version or nuget.get("effective_version"),
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
        "scores": scores,
        "overall": overall,
        "rating": rating,
    }

    if json_out or not pdf_out:
        print(json.dumps(result, indent=2))

    if pdf_out:
        make_pdf_report(pdf_out, package, version, nuget, gh, vulns, scores, overall, rating)
        print(f"PDF written: {pdf_out}")


def parse_packages_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out: List[Tuple[str, Optional[str]]] = []
    # packages.lock.json has TFMs at top-level "dependencies"
    deps = data.get("dependencies") or {}
    for _, tfm_deps in (deps.items() if isinstance(deps, dict) else []):
        if not isinstance(tfm_deps, dict):
            continue
        for name, meta in tfm_deps.items():
            ver = None
            if isinstance(meta, dict):
                ver = meta.get("resolved") or meta.get("version")
            out.append((name, ver))
    # Fallback: "packages" list
    if not out and isinstance(data.get("packages"), list):
        for p in data["packages"]:
            name = p.get("id") or p.get("name")
            ver = p.get("version")
            if name:
                out.append((name, ver))
    return out


def _discover_lockfile(start_dir: str) -> Optional[str]:
    # Prefer a lockfile in the current directory
    candidate = os.path.join(start_dir, "packages.lock.json")
    if os.path.isfile(candidate):
        return candidate
    # Otherwise, find the first occurrence recursively
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
    # Deduplicate by package name, prefer a resolved version if available
    best: Dict[str, Optional[str]] = {}
    for name, ver in items:
        if name not in best or (ver and not best[name]):
            best[name] = ver
    # Sort by name
    return sorted(best.items(), key=lambda kv: kv[0].lower())


def audit_lockfile(lock_path: str, pdf_out: Optional[str], json_out: bool):
    items = parse_packages_lock(lock_path)
    results = []
    for name, ver in items[:50]:  # cap for speed
        nuget = summarize_nuget(name, ver)
        gh = get_github_repo_stats(nuget.get("repo_url")) if nuget.get("repo_url") else {}
        vulns = query_osv_vulns(name, nuget.get("effective_version"))
        scores, overall, rating = compute_risk(nuget, vulns, gh)
        results.append({
            "package": name,
            "version": ver or nuget.get("effective_version"),
            "overall": overall,
            "rating": rating,
            "vulnerabilities": len(vulns),
        })
    payload = {"lockfile": lock_path, "results": results}
    if json_out or not pdf_out:
        print(json.dumps(payload, indent=2))

    if pdf_out:
        # Simple PDF: one page with top results table
        if not (plt and PdfPages):
            raise RuntimeError("matplotlib is required for PDF output. pip install matplotlib")
        with PdfPages(pdf_out) as pdf:
            fig, ax = plt.subplots(figsize=(10, 8), dpi=150, constrained_layout=True)
            ax.axis("off")
            ax.set_title(f"NuGet Lockfile Audit — {os.path.basename(lock_path)}", fontsize=14, fontweight="bold")
            rows = []
            for r in results:
                rows.append([r["package"], r["version"] or "n/a", r["rating"], r["overall"], r["vulnerabilities"]])
            table = ax.table(cellText=rows, colLabels=["Package", "Version", "Rating", "Score", "Vulns"], loc="center", cellLoc="left")
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.2)
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)
        print(f"PDF written: {pdf_out}")


def main():
    ap = argparse.ArgumentParser(description="Audit security of C# NuGet modules and generate a PDF report.")
    # Global --list to print auditable packages from a packages.lock.json
    ap.add_argument("--list", action="store_true", help="List packages from packages.lock.json that can be audited")
    ap.add_argument("--path", help="Path to packages.lock.json for --list (defaults to auto-detect)")
    sub = ap.add_subparsers(dest="cmd", required=False)

    ap_pkg = sub.add_parser("package", help="Audit a single package")
    ap_pkg.add_argument("--name", required=True, help="NuGet package ID")
    ap_pkg.add_argument("--version", help="Specific version (defaults to latest)")
    ap_pkg.add_argument("--pdf", help="Path to output PDF (if omitted, prints JSON only)")
    ap_pkg.add_argument("--json", action="store_true", help="Print JSON to stdout")

    ap_lock = sub.add_parser("lockfile", help="Audit packages.lock.json")
    ap_lock.add_argument("--path", required=True, help="Path to packages.lock.json")
    ap_lock.add_argument("--pdf", help="Path to output PDF (if omitted, prints JSON only)")
    ap_lock.add_argument("--json", action="store_true", help="Print JSON to stdout")

    args = ap.parse_args()

    # Handle --list early, no subcommand required
    if getattr(args, "list", False):
        items = list_auditable_packages(getattr(args, "path", None))
        if not items:
            sys.exit(1)
        for name, ver in items:
            print(f"{name}" + (f"=={ver}" if ver else ""))
        return

    if args.cmd == "package":
        audit_package(args.name, args.version, args.pdf, args.json)
    elif args.cmd == "lockfile":
        audit_lockfile(args.path, args.pdf, args.json)


if __name__ == "__main__":
    main()