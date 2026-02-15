#!/usr/bin/env python3
"""
sbom_supply_chain_risk.py

Compute supply-chain risk for an SPDX-ish SBOM JSON (like GitHub Dependency Graph SPDX export),
WITHOUT using GitHub Dependabot.

Primary vulnerability source: OSV.dev API (query/querybatch + vulns/{id})
Docs:
- POST /v1/query, /v1/querybatch: https://google.github.io/osv.dev/post-v1-query/ and /post-v1-querybatch/
- OSV range limitation discussion (no direct range querying): https://github.com/google/osv.dev/discussions/1852

Usage:
  python sbom_supply_chain_risk.py sbom.json --out report.json
  python sbom_supply_chain_risk.py sbom.json --format markdown
  python sbom_supply_chain_risk.py sbom.json --assume-version lowerbound
  python sbom_supply_chain_risk.py sbom.json --assume-version none   (skip vuln queries unless exact version is known)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"  # /{id}

# -----------------------------
# Helpers: parsing + scoring
# -----------------------------

SEMVER_RE = re.compile(r"(?i)\b(\d+)\.(\d+)\.(\d+)(?:[-+~.^<>=! ]|$)")
EXACT_RE = re.compile(r"^\s*(==|=)?\s*v?(\d+\.\d+\.\d+)\s*$")
LOWERBOUND_RE = re.compile(r"^\s*>=\s*v?(\d+\.\d+\.\d+)\s*$")
RANGE_LOWERBOUND_RE = re.compile(r"^\s*>=\s*v?(\d+\.\d+\.\d+)\s*,\s*<\s*v?(\d+\.\d+\.\d+)\s*$")

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def now_iso() -> str:
    # ISO-ish; avoid timezone pitfalls for this script’s output.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def purl_from_pkg(pkg: Dict[str, Any]) -> Optional[str]:
    # Your structure puts purl in externalRefs[]
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str):
            return ref["referenceLocator"]
    return None

def guess_version_from_versioninfo(version_info: Optional[str], strategy: str) -> Optional[str]:
    """
    strategy:
      - exact: only accept exact versions
      - lowerbound: accept exact, else for '>= x.y.z' use x.y.z, for '>= x,< y' use x
      - none: never guess (only exact pinned versions)
    """
    if not version_info or not isinstance(version_info, str):
        return None

    s = version_info.strip()

    # exact versions like "2.31.0" or "== 2.31.0"
    m = EXACT_RE.match(s)
    if m:
        return m.group(2)

    if strategy == "exact" or strategy == "none":
        return None

    # common constraints in your SBOM
    m = LOWERBOUND_RE.match(s)
    if m:
        return m.group(1)

    m = RANGE_LOWERBOUND_RE.match(s)
    if m:
        return m.group(1)

    # if it's something like ">= 1.0.0" but with extra text, try to extract first semver
    m = SEMVER_RE.search(s)
    if m:
        return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"

    return None

def is_floating_branch_or_unpinned(pkg: Dict[str, Any]) -> bool:
    # Heuristic: git dependency on "main/master" or non-commit ref
    vi = (pkg.get("versionInfo") or "").strip().lower()
    if vi in {"main", "master", "head", "trunk"}:
        return True
    # if downloadLocation is git+https://... without @<sha> style pin
    dl = (pkg.get("downloadLocation") or "").strip().lower()
    if dl.startswith("git+") and ("@" not in dl):
        return True
    return False

def base_hygiene_risk(pkg: Dict[str, Any], has_exact_version: bool) -> Tuple[int, List[str]]:
    """
    Returns (points, reasons)
    """
    points = 0
    reasons: List[str] = []

    # Version pinning is a big deal
    if not has_exact_version:
        points += 12
        reasons.append("Version is not pinned to an exact release (range/unknown).")

    # Floating branches are worse than ranges
    if is_floating_branch_or_unpinned(pkg):
        points += 18
        reasons.append("Dependency appears to be floating (e.g., 'main' / unpinned git ref).")

    # SBOM completeness hints
    if (pkg.get("downloadLocation") == "NOASSERTION"):
        points += 5
        reasons.append("downloadLocation=NOASSERTION.")

    if pkg.get("filesAnalyzed") is False:
        points += 3
        reasons.append("filesAnalyzed=false (less evidence about actual contents).")

    return points, reasons

def extract_cvss_score(vuln: Dict[str, Any]) -> Optional[float]:
    """
    OSV records can contain a 'severity' array with CVSS vectors, or other ecosystem-specific severities.
    We'll try:
      - vuln['severity'][] with type 'CVSS_V3'/'CVSS_V2' and a score field (if present)
      - else None
    """
    sev = vuln.get("severity")
    if isinstance(sev, list):
        for item in sev:
            if not isinstance(item, dict):
                continue
            score = item.get("score")
            if isinstance(score, (int, float)):
                return float(score)
            # Sometimes score is not numeric; ignore.
    return None

def extract_osv_severity_label(vuln: Dict[str, Any]) -> Optional[str]:
    """
    Try to find a text severity like CRITICAL/HIGH/MEDIUM/LOW from ecosystem_specific.
    """
    affected = vuln.get("affected")
    if isinstance(affected, list):
        for a in affected:
            if not isinstance(a, dict):
                continue
            eco = a.get("ecosystem_specific")
            if isinstance(eco, dict):
                sev = eco.get("severity")
                if isinstance(sev, str) and sev.strip():
                    return sev.strip().upper()
    return None

def vuln_points(vuln: Dict[str, Any]) -> Tuple[int, str]:
    """
    Convert a vuln record to risk points.
    Prefer CVSS score if present; else map labels.
    """
    cvss = extract_cvss_score(vuln)
    if cvss is not None:
        # CVSS 0-10 -> points 0-30 (nonlinear-ish)
        pts = int(round(clamp((cvss / 10.0) ** 1.3 * 30.0, 0, 30)))
        return pts, f"CVSS={cvss:.1f}"

    label = extract_osv_severity_label(vuln)
    if label:
        mapping = {"CRITICAL": 30, "HIGH": 22, "MEDIUM": 12, "LOW": 6}
        if label in mapping:
            return mapping[label], f"Severity={label}"

    # Unknown severity info -> conservative small bump
    return 8, "Severity=UNKNOWN"

# -----------------------------
# OSV querying
# -----------------------------

@dataclasses.dataclass
class PackageFinding:
    spdx_id: str
    name: str
    purl: Optional[str]
    version_info: Optional[str]
    assumed_version: Optional[str]
    hygiene_points: int
    hygiene_reasons: List[str]
    vuln_ids: List[str]
    vulns: List[Dict[str, Any]]
    vuln_points_total: int
    risk_points_total: int

def osv_querybatch(queries: List[Dict[str, Any]], timeout: int = 30) -> Dict[str, Any]:
    resp = requests.post(OSV_QUERYBATCH_URL, json={"queries": queries}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def osv_get_vuln(vuln_id: str, timeout: int = 30) -> Dict[str, Any]:
    resp = requests.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def build_osv_query(purl: str, version: Optional[str]) -> Dict[str, Any]:
    if version:
        # OSV requires version not embedded in purl if version field used; our purls are unversioned.
        return {"package": {"purl": purl}, "version": version}
    return {"package": {"purl": purl}}

# -----------------------------
# SBOM parsing
# -----------------------------

def load_sbom(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_root_spdx_id(sbom: Dict[str, Any]) -> Optional[str]:
    # Root is the element that document DESCRIBES
    for rel in sbom.get("relationships", []) or []:
        if rel.get("spdxElementId") == "SPDXRef-DOCUMENT" and rel.get("relationshipType") == "DESCRIBES":
            return rel.get("relatedSpdxElement")
    return None

def collect_dep_spdx_ids(sbom: Dict[str, Any], root_id: str) -> List[str]:
    deps = []
    for rel in sbom.get("relationships", []) or []:
        if rel.get("spdxElementId") == root_id and rel.get("relationshipType") == "DEPENDS_ON":
            rid = rel.get("relatedSpdxElement")
            if isinstance(rid, str):
                deps.append(rid)
    return deps

def index_packages(sbom: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for pkg in sbom.get("packages", []) or []:
        spdx_id = pkg.get("SPDXID")
        if isinstance(spdx_id, str):
            idx[spdx_id] = pkg
    return idx

# -----------------------------
# Risk model + reporting
# -----------------------------

def compute_risk(
    sbom_doc: Dict[str, Any],
    assume_version: str,
    include_unversioned_osv_queries: bool,
    fetch_vuln_details: bool,
    osv_timeout: int,
    max_vulns_per_pkg: int,
) -> Dict[str, Any]:
    sbom = sbom_doc.get("sbom", sbom_doc)  # allow either {"sbom":{...}} or direct
    root_id = find_root_spdx_id(sbom)
    if not root_id:
        raise ValueError("Could not determine root package (missing SPDXRef-DOCUMENT DESCRIBES relationship).")

    pkg_index = index_packages(sbom)
    root_pkg = pkg_index.get(root_id)
    if not root_pkg:
        raise ValueError(f"Root package SPDXID '{root_id}' not found in packages[].")

    dep_ids = collect_dep_spdx_ids(sbom, root_id)

    findings: List[PackageFinding] = []
    osv_queries: List[Dict[str, Any]] = []
    osv_query_meta: List[Tuple[str, str, Optional[str], Optional[str]]] = []  # (dep_spdx_id, name, purl, assumed_version)

    # Build findings + OSV querybatch payload
    for dep_id in dep_ids:
        pkg = pkg_index.get(dep_id, {})
        name = str(pkg.get("name") or dep_id)
        vi = pkg.get("versionInfo")
        purl = purl_from_pkg(pkg)

        assumed = guess_version_from_versioninfo(vi, strategy=assume_version)
        has_exact = bool(assumed) and bool(EXACT_RE.match((vi or "").strip()) or EXACT_RE.match((assumed or "").strip()))

        # Hygiene scoring
        hygiene_pts, hygiene_reasons = base_hygiene_risk(pkg, has_exact_version=has_exact)

        # Decide OSV query eligibility
        do_osv = False
        if purl:
            if assumed is not None:
                do_osv = True
            elif include_unversioned_osv_queries:
                do_osv = True  # may return broad results; user-controlled

        if do_osv and purl:
            osv_queries.append(build_osv_query(purl, assumed))
            osv_query_meta.append((dep_id, name, purl, assumed))

        findings.append(
            PackageFinding(
                spdx_id=dep_id,
                name=name,
                purl=purl,
                version_info=vi,
                assumed_version=assumed,
                hygiene_points=hygiene_pts,
                hygiene_reasons=hygiene_reasons,
                vuln_ids=[],
                vulns=[],
                vuln_points_total=0,
                risk_points_total=hygiene_pts,
            )
        )

    # Query OSV in bulk
    osv_results_by_spdx: Dict[str, List[str]] = {}
    if osv_queries:
        batch = osv_querybatch(osv_queries, timeout=osv_timeout)
        results = batch.get("results", [])
        # results order matches input order
        for (dep_id, _name, _purl, _assumed), res in zip(osv_query_meta, results):
            vulns = res.get("vulns") or []
            ids = []
            for v in vulns:
                vid = v.get("id")
                if isinstance(vid, str):
                    ids.append(vid)
            osv_results_by_spdx[dep_id] = ids

    # Optionally fetch vuln details and compute vuln points
    for f in findings:
        ids = osv_results_by_spdx.get(f.spdx_id, [])
        # limit to avoid enormous downloads
        ids = ids[:max_vulns_per_pkg]
        f.vuln_ids = ids

        vuln_pts_total = 0
        vulns: List[Dict[str, Any]] = []
        if fetch_vuln_details and ids:
            for vid in ids:
                try:
                    vdoc = osv_get_vuln(vid, timeout=osv_timeout)
                except requests.RequestException as e:
                    vdoc = {"id": vid, "error": str(e)}
                pts, why = vuln_points(vdoc) if "error" not in vdoc else (5, "FetchError")
                vuln_pts_total += pts
                vdoc["_risk_points"] = pts
                vdoc["_risk_basis"] = why
                vulns.append(vdoc)
        else:
            # if we didn't fetch details, approximate:
            # each vuln id contributes a small default (because we can't severity-rank)
            vuln_pts_total = min(30, 6 * len(ids))

        f.vuln_points_total = int(vuln_pts_total)
        f.risk_points_total = int(f.hygiene_points + f.vuln_points_total)
        f.vulns = vulns

    # Aggregate
    total_hygiene = sum(f.hygiene_points for f in findings)
    total_vuln_pts = sum(f.vuln_points_total for f in findings)
    total_points_raw = total_hygiene + total_vuln_pts

    # Normalize to 0..100-ish using a saturating curve
    overall = int(round(100.0 * (1.0 - math.exp(-total_points_raw / 80.0))))
    overall = int(clamp(overall, 0, 100))

    def label(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 55:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    # Build report object
    report = {
        "generated_at": now_iso(),
        "root": {
            "spdx_id": root_id,
            "name": root_pkg.get("name"),
            "versionInfo": root_pkg.get("versionInfo"),
            "downloadLocation": root_pkg.get("downloadLocation"),
        },
        "settings": {
            "assume_version": assume_version,
            "include_unversioned_osv_queries": include_unversioned_osv_queries,
            "fetch_vuln_details": fetch_vuln_details,
            "max_vulns_per_pkg": max_vulns_per_pkg,
        },
        "summary": {
            "dependency_count": len(findings),
            "total_hygiene_points": total_hygiene,
            "total_vuln_points": total_vuln_pts,
            "overall_score_0_100": overall,
            "overall_label": label(overall),
        },
        "packages": [
            {
                "spdx_id": f.spdx_id,
                "name": f.name,
                "purl": f.purl,
                "versionInfo": f.version_info,
                "assumed_version_for_osv": f.assumed_version,
                "hygiene_points": f.hygiene_points,
                "hygiene_reasons": f.hygiene_reasons,
                "vuln_ids": f.vuln_ids,
                "vuln_points_total": f.vuln_points_total,
                "risk_points_total": f.risk_points_total,
                "vulns": f.vulns,  # may be empty if fetch_vuln_details=false
            }
            for f in sorted(findings, key=lambda x: x.risk_points_total, reverse=True)
        ],
    }
    return report

def to_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    root = report["root"]
    lines: List[str] = []
    lines.append(f"# Supply Chain Risk Report\n")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Root: **{root.get('name')}** (`{root.get('spdx_id')}`)")
    lines.append(f"- Dependencies: **{s['dependency_count']}**")
    lines.append(f"- Overall risk: **{s['overall_label']}** (score **{s['overall_score_0_100']} / 100**)\n")
    lines.append("## Top risky packages\n")
    lines.append("| Package | VersionInfo | Assumed version | Vulns | Hygiene pts | Vuln pts | Total pts |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for p in report["packages"][:20]:
        lines.append(
            f"| `{p['name']}` | `{p.get('versionInfo')}` | `{p.get('assumed_version_for_osv')}` "
            f"| {len(p.get('vuln_ids') or [])} | {p['hygiene_points']} | {p['vuln_points_total']} | {p['risk_points_total']} |"
        )

    lines.append("\n## Notes\n")
    lines.append("- If `versionInfo` is a range (e.g., `>= 2.31.0`) and no lockfile is available, the script can only do best-effort OSV checks.")
    lines.append("- Best results happen with pinned versions (lockfiles) because OSV queries are version-based.\n")
    return "\n".join(lines)

# -----------------------------
# CLI
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Compute supply-chain risk from an SPDX-ish SBOM JSON using OSV (no Dependabot).")
    ap.add_argument("sbom_json", help="Path to JSON file (either {\"sbom\": {...}} or direct SPDX JSON).")
    ap.add_argument("--out", default="", help="Write report to this path (json or md depending on --format). Default: stdout")
    ap.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format.")
    ap.add_argument(
        "--assume-version",
        choices=["none", "exact", "lowerbound"],
        default="lowerbound",
        help="How to derive a query version from versionInfo constraints. 'none' = only query if exact version is present.",
    )
    ap.add_argument(
        "--include-unversioned-osv-queries",
        action="store_true",
        help="Also query OSV with package purl even when no version is known (can be broad/noisy).",
    )
    ap.add_argument(
        "--no-vuln-details",
        action="store_true",
        help="Don't fetch /v1/vulns/{id} details; faster, but severity scoring becomes approximate.",
    )
    ap.add_argument("--osv-timeout", type=int, default=30, help="HTTP timeout seconds for OSV calls.")
    ap.add_argument("--max-vulns-per-pkg", type=int, default=50, help="Limit fetched vuln IDs per package to avoid huge downloads.")

    args = ap.parse_args()

    doc = load_sbom(args.sbom_json)
    report = compute_risk(
        doc,
        assume_version=args.assume_version,
        include_unversioned_osv_queries=bool(args.include_unversioned_osv_queries),
        fetch_vuln_details=not args.no_vuln_details,
        osv_timeout=args.osv_timeout,
        max_vulns_per_pkg=args.max_vulns_per_pkg,
    )

    if args.format == "markdown":
        out_text = to_markdown(report)
    else:
        out_text = json.dumps(report, indent=2, ensure_ascii=False)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text)
    else:
        print(out_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
