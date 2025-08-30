#!/usr/bin/env python3
import os
import sys
import json
import requests
import argparse
import warnings
import configparser
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                           GitHub Audit Script                               │
# │                                                                             │
# │  Features:                                                                  │
# │   - Configurable scoring via INI (use --config or --write-default-config)   │
# │   - Repo activity, license, security policy, language, issues, signed commits│
# │   - Optional: dependency analysis + Dependabot vulnerabilities (scored)     │
# │   - Robust HTTP: timeouts, retries, rate-limit handling                     │
# │                                                                             │
# │  Env vars:                                                                  │
# │   - GITHUB_TOKEN       : GitHub token (recommended to avoid rate limits)    │
# │   - GITHUB_API_BASE    : Override API base (e.g., GitHub Enterprise)        │
# └─────────────────────────────────────────────────────────────────────────────┘

API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "github-audit-script/1.0"
}
if GITHUB_TOKEN:
    # Both 'token' and 'Bearer' currently work. 'Bearer' matches GH docs for fine-grained tokens.
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
else:
    print("⚠️ Warning: No GITHUB_TOKEN set. You may hit rate limits quickly.")

DEFAULT_CONFIG_TEXT = """\
[recent_commit]
good_days = 90
abandoned_days = 365
score = 1

[active_devs]
threshold = 5
score = 1

[license_scores]
mit = 1
apache = 1
gpl = 0.5
mpl = 0
lgpl = 0
other = -1

[security_policy]
score = 1

[language]
popular = Python, JavaScript, Go, Rust, Swift, Kotlin, Java, C#
score = 1

[issue_tracking]
score = 1

[issue_resolution]
min_issues = 10
ratio_threshold = 0.6
score_pass = 1
score_fail = -1

[signed_commits]
ratio_threshold = 0.5
score = 1

[dependency_analysis]
score = 1

[vulnerabilities]
critical_weight = 4
high_weight = 2
medium_weight = 1
low_weight = 0.5
none_weight = 0
max_penalty = 3
score_pass = 1
score_fail = -1
"""

# ---------------------------- Utilities / HTTP -------------------------------

def write_default_config(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(DEFAULT_CONFIG_TEXT)
    print(f"✅ Wrote default config to {path}")

def load_config(path=None):
    cfg = configparser.ConfigParser()
    cfg.read_string(DEFAULT_CONFIG_TEXT)
    if path:
        with open(path, "r", encoding="utf-8") as f:
            cfg.read_file(f)

    def get_float(section, option, fallback):
        try:
            return cfg.getfloat(section, option, fallback=fallback)
        except Exception:
            return fallback

    def get_int(section, option, fallback):
        try:
            return cfg.getint(section, option, fallback=fallback)
        except Exception:
            return fallback

    def get_list(section, option, fallback_list):
        raw = cfg.get(section, option, fallback=",".join(fallback_list))
        return [x.strip() for x in raw.split(",") if x.strip()]

    return {
        "recent_commit": {
            "good_days": get_int("recent_commit", "good_days", 90),
            "abandoned_days": get_int("recent_commit", "abandoned_days", 365),
            "score": get_float("recent_commit", "score", 1),
        },
        "active_devs": {
            "threshold": get_int("active_devs", "threshold", 5),
            "score": get_float("active_devs", "score", 1),
        },
        "license_scores": {
            "mit": get_float("license_scores", "mit", 1),
            "apache": get_float("license_scores", "apache", 1),
            "gpl": get_float("license_scores", "gpl", 0.5),
            "mpl": get_float("license_scores", "mpl", 0),
            "lgpl": get_float("license_scores", "lgpl", 0),
            "other": get_float("license_scores", "other", -1),
        },
        "security_policy": {
            "score": get_float("security_policy", "score", 1),
        },
        "language": {
            "popular": get_list("language", "popular",
                                ["Python","JavaScript","Go","Rust","Swift","Kotlin","Java","C#"]),
            "score": get_float("language", "score", 1),
        },
        "issue_tracking": {
            "score": get_float("issue_tracking", "score", 1),
        },
        "issue_resolution": {
            "min_issues": get_int("issue_resolution", "min_issues", 10),
            "ratio_threshold": get_float("issue_resolution", "ratio_threshold", 0.6),
            "score_pass": get_float("issue_resolution", "score_pass", 1),
            "score_fail": get_float("issue_resolution", "score_fail", -1),
        },
        "signed_commits": {
            "ratio_threshold": get_float("signed_commits", "ratio_threshold", 0.5),
            "score": get_float("signed_commits", "score", 1),
        },
        "dependency_analysis": {
            "score": get_float("dependency_analysis", "score", 1),
        },
        "vulnerabilities": {
            "critical_weight": get_float("vulnerabilities", "critical_weight", 4),
            "high_weight": get_float("vulnerabilities", "high_weight", 2),
            "medium_weight": get_float("vulnerabilities", "medium_weight", 1),
            "low_weight": get_float("vulnerabilities", "low_weight", 0.5),
            "none_weight": get_float("vulnerabilities", "none_weight", 0),
            "max_penalty": get_float("vulnerabilities", "max_penalty", 3),
            "score_pass": get_float("vulnerabilities", "score_pass", 1),
            "score_fail": get_float("vulnerabilities", "score_fail", -1),
        },
    }

def _requests_session():
    retry = Retry(
        total=5,
        backoff_factor=1.2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD", "OPTIONS")
    )
    sess = requests.Session()
    sess.headers.update(HEADERS)
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.mount("http://", HTTPAdapter(max_retries=retry))
    return sess

SESSION = _requests_session()

def check_rate_limit(response):
    if response.status_code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
        reset_ts = int(response.headers.get("X-RateLimit-Reset", 0))
        reset_time = datetime.utcfromtimestamp(reset_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"❗ GitHub API rate limit reached. Try again after {reset_time}.")
        sys.exit(1)

def _get(url, verify_ssl, **params):
    r = SESSION.get(url, verify=verify_ssl, timeout=15, params=params or None)
    check_rate_limit(r)
    r.raise_for_status()
    return r

# ---------------------------- GitHub helpers ---------------------------------

def get_repo_info(owner, repo, verify_ssl):
    url = f"{API_BASE}/repos/{owner}/{repo}"
    try:
        r = _get(url, verify_ssl)
        data = r.json()
        license_info = data.get("license")
        license_name = license_info.get("name") if license_info else "None"
        return {
            "name": data.get("full_name"),
            "license": license_name,
            "language": data.get("language", "Unknown"),
            "issue_tracking_enabled": data.get("has_issues", False),
            "archived": data.get("archived", False),
            "disabled": data.get("disabled", False),
        }
    except Exception as e:
        print(f"⚠️ Error fetching repo info: {e}")
        return {"name": f"{owner}/{repo}", "license": "Error", "language": "Unknown",
                "issue_tracking_enabled": False, "archived": False, "disabled": False}

def get_issues_count(owner, repo, verify_ssl):
    counts = {"open": 0, "closed": 0}
    base = f"{API_BASE}/search/issues"
    for state in ('open', 'closed'):
        try:
            q = f"repo:{owner}/{repo} type:issue state:{state}"
            r = _get(base, verify_ssl, q=q)
            counts[state] = r.json().get('total_count', 0)
        except Exception as e:
            print(f"⚠️ Error fetching {state} issues: {e}")
    return counts

def get_last_commit_date(owner, repo, verify_ssl):
    url = f"{API_BASE}/repos/{owner}/{repo}/commits"
    try:
        r = _get(url, verify_ssl, per_page=1)
        commits = r.json()
        if commits:
            return commits[0]['commit']['committer']['date']
    except Exception as e:
        print(f"⚠️ Error fetching commits: {e}")
    return None

def get_active_developers(owner, repo, verify_ssl, days=90):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace('+00:00', 'Z')
    devs = set()
    page = 1
    while True:
        url = f"{API_BASE}/repos/{owner}/{repo}/commits"
        try:
            r = _get(url, verify_ssl, since=since, per_page=100, page=page)
            commits = r.json()
            if not commits:
                break
            for c in commits:
                author = c.get('author')
                login = author.get('login') if author else None
                if login and not login.endswith("[bot]"):
                    devs.add(login)
            page += 1
        except Exception as e:
            print(f"⚠️ Error fetching active developers: {e}")
            break
    return len(devs)

def has_security_policy(owner, repo, verify_ssl):
    paths = ('.github/SECURITY.md', 'SECURITY.md', 'docs/SECURITY.md')
    for p in paths:
        url = f"{API_BASE}/repos/{owner}/{repo}/contents/{p}"
        try:
            r = SESSION.get(url, verify=verify_ssl, timeout=15)
            check_rate_limit(r)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            continue
    return False

def count_signed_commits(owner, repo, verify_ssl, max_commits=500):
    per_page, page = 100, 1
    signed, total = 0, 0
    while total < max_commits:
        url = f"{API_BASE}/repos/{owner}/{repo}/commits"
        try:
            r = _get(url, verify_ssl, per_page=per_page, page=page)
            commits = r.json()
            if not commits:
                break
            for c in commits:
                if total >= max_commits:
                    break
                ver = c.get('commit', {}).get('verification', {})
                if ver.get('verified'):
                    signed += 1
                total += 1
            page += 1
        except Exception as e:
            print(f"⚠️ Error fetching signed commits (page {page}): {e}")
            break
    return signed, total

# ---------------------- Dependency/SBOM & Vulnerabilities --------------------

def get_repo_sbom(owner, repo, verify_ssl):
    """
    Returns (enabled: bool, sbom_json: dict|None).
    200 → enabled with SBOM payload
    202 → enabled but SBOM being generated (treat as enabled, sbom=None)
    404/451 → disabled or insufficient permissions
    """
    url = f"{API_BASE}/repos/{owner}/{repo}/dependency-graph/sbom"
    try:
        r = SESSION.get(url, verify=verify_ssl, timeout=20)
        check_rate_limit(r)
        if r.status_code == 200:
            return True, r.json()
        if r.status_code == 202:
            return True, None
        return False, None
    except requests.RequestException as e:
        print(f"⚠️ Error fetching SBOM: {e}")
        return False, None

def parse_spdx_dependency_count(sbom_json):
    """
    Parse SPDX 2.3 JSON SBOM and return total package count.
    """
    if not sbom_json:
        return 0
    sbom = sbom_json.get("sbom") or {}
    packages = sbom.get("packages") or []
    return len(packages)

def get_dependabot_alerts(owner, repo, verify_ssl):
    """
    Returns (alerts_list, counts_by_severity).
    For private repos, token needs security_events scope.
    """
    url = f"{API_BASE}/repos/{owner}/{repo}/dependabot/alerts"
    params = {"state": "open", "per_page": 100}
    alerts, page = [], 1
    try:
        while True:
            params["page"] = page
            r = SESSION.get(url, params=params, verify=verify_ssl, timeout=20)
            check_rate_limit(r)
            if r.status_code == 404:
                return [], {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            alerts.extend(batch)
            if len(batch) < 100:
                break
            page += 1
    except requests.RequestException as e:
        print(f"⚠️ Error fetching Dependabot alerts: {e}")
        return [], {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for a in alerts:
        sev = (a.get("security_vulnerability", {}).get("severity") or "none").lower()
        if sev not in severities:
            sev = "none"
        severities[sev] += 1
    return alerts, severities

# ---------------------------- Scoring ----------------------------------------

def score_repo(last_commit_date, num_devs, license_type, has_policy,
               language, has_issues, issue_counts,
               signed_commits, total_sampled,
               dep_graph_enabled, vuln_counts,
               config):
    raw_score = 0.0
    abandoned = False
    breakdown = {}

    denom = 0.0  # sum of max positive contributions

    # 1) Recent commit
    rc = config["recent_commit"]
    if last_commit_date:
        last = datetime.strptime(last_commit_date, "%Y-%m-%dT%H:%M:%SZ")
        days = (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).days
        passed = days < rc["good_days"]
        score_val = rc["score"] if passed else 0.0
        raw_score += score_val
        denom += max(rc["score"], 0.0)
        if days > rc["abandoned_days"]:
            abandoned = True
        breakdown['recent_commit'] = {
            'score': score_val if passed else 0.0,
            'value': days,
            'thresholds': {'good_days': rc["good_days"], 'abandoned_days': rc["abandoned_days"]},
            'weight': rc["score"]
        }
    else:
        denom += max(rc["score"], 0.0)
        abandoned = True
        breakdown['recent_commit'] = {
            'score': 0.0,
            'value': None,
            'thresholds': {'good_days': rc["good_days"], 'abandoned_days': rc["abandoned_days"]},
            'weight': rc["score"]
        }

    # 2) Active developers
    ad = config["active_devs"]
    dev_ok = num_devs >= ad["threshold"]
    score_val = ad["score"] if dev_ok else 0.0
    raw_score += score_val
    denom += max(ad["score"], 0.0)
    breakdown['active_devs'] = {
        'score': score_val,
        'value': num_devs,
        'threshold': ad["threshold"],
        'weight': ad["score"]
    }

    # 3) License
    lic = (license_type or "").lower()
    ls = config["license_scores"]
    if "mit" in lic:
        lic_score = ls["mit"]; family = "MIT"
    elif "apache" in lic:
        lic_score = ls["apache"]; family = "Apache"
    elif "gpl" in lic:
        lic_score = ls["gpl"]; family = "GPL"
    elif "mpl" in lic:
        lic_score = ls["mpl"]; family = "MPL"
    elif "lgpl" in lic:
        lic_score = ls["lgpl"]; family = "LGPL"
    else:
        lic_score = ls["other"]; family = "Other"
    raw_score += lic_score
    denom += max(ls["mit"], ls["apache"], ls["gpl"], ls["mpl"], ls["lgpl"], 0.0)
    breakdown['license'] = {
        'score': lic_score,
        'value': license_type,
        'rules': dict(ls),
        'matched_family': family
    }

    # 4) Security policy
    sp = config["security_policy"]
    score_val = sp["score"] if has_policy else 0.0
    raw_score += score_val
    denom += max(sp["score"], 0.0)
    breakdown['security_policy'] = {
        'score': score_val,
        'value': has_policy,
        'weight': sp["score"]
    }

    # 5) Language (case-insensitive)
    ln = config["language"]
    lang_ok = (language or "").strip().lower() in [x.lower() for x in ln["popular"]]
    score_val = ln["score"] if lang_ok else 0.0
    raw_score += score_val
    denom += max(ln["score"], 0.0)
    breakdown['language'] = {
        'score': score_val,
        'value': language,
        'popular_list': ln["popular"],
        'weight': ln["score"]
    }

    # 6) Issue tracking enabled
    it = config["issue_tracking"]
    score_val = it["score"] if has_issues else 0.0
    raw_score += score_val
    denom += max(it["score"], 0.0)
    breakdown['issue_tracking'] = {
        'score': score_val,
        'value': has_issues,
        'weight': it["score"]
    }

    # 7) Issue resolution
    ir = config["issue_resolution"]
    total_issues = issue_counts['open'] + issue_counts['closed']
    if total_issues > ir["min_issues"]:
        ratio = issue_counts['closed'] / total_issues if total_issues else 0
        pass_ok = ratio >= ir["ratio_threshold"]
        score_val = ir["score_pass"] if pass_ok else ir["score_fail"]
        raw_score += score_val
        denom += max(ir["score_pass"], 0.0)
        breakdown['issue_resolution'] = {
            'score': score_val,
            'value': ratio,
            'threshold': ir["ratio_threshold"],
            'min_issues': ir["min_issues"],
            'weights': {'pass': ir["score_pass"], 'fail': ir["score_fail"]}
        }
    else:
        breakdown['issue_resolution'] = {
            'score': 0.0,
            'value': total_issues,
            'threshold': ir["min_issues"],
            'weights': {'pass': ir["score_pass"], 'fail': ir["score_fail"]}
        }

    # 8) Signed commits (>= threshold)
    sc = config["signed_commits"]
    if total_sampled > 0:
        ratio = signed_commits / total_sampled
        sign_ok = ratio >= sc["ratio_threshold"]
        score_val = sc["score"] if sign_ok else 0.0
        raw_score += score_val
        denom += max(sc["score"], 0.0)
        breakdown['signed_commits'] = {
            'score': score_val,
            'value': ratio,
            'threshold': sc["ratio_threshold"],
            'sampled': total_sampled,
            'weight': sc["score"]
        }

    # 9) Dependency analysis enabled (if we checked)
    da = config["dependency_analysis"]
    if dep_graph_enabled is not None:
        score_val = da["score"] if dep_graph_enabled else 0.0
        raw_score += score_val
        denom += max(da["score"], 0.0)
        breakdown['dependency_analysis'] = {
            'score': score_val,
            'value': dep_graph_enabled,
            'weight': da["score"]
        }

    # 10) Vulnerabilities (Dependabot) — only if we checked
    vu = config["vulnerabilities"]
    if vuln_counts is not None:
        total_open = sum(vuln_counts.values())
        if total_open == 0:
            raw_score += vu["score_pass"]
            denom += max(vu["score_pass"], 0.0)
            breakdown['vulnerabilities'] = {
                'score': vu["score_pass"],
                'value': vuln_counts,
                'weights': {
                    'critical': vu["critical_weight"], 'high': vu["high_weight"],
                    'medium': vu["medium_weight"], 'low': vu["low_weight"], 'none': vu["none_weight"]
                },
                'max_penalty': vu["max_penalty"],
                'notes': 'No open alerts'
            }
        else:
            penalty = (
                vuln_counts.get("critical", 0) * vu["critical_weight"]
                + vuln_counts.get("high", 0) * vu["high_weight"]
                + vuln_counts.get("medium", 0) * vu["medium_weight"]
                + vuln_counts.get("low", 0) * vu["low_weight"]
                + vuln_counts.get("none", 0) * vu["none_weight"]
            )
            penalty = min(penalty, vu["max_penalty"])
            score_val = vu["score_fail"] - penalty
            raw_score += score_val
            denom += max(vu["score_pass"], 0.0)
            breakdown['vulnerabilities'] = {
                'score': score_val,
                'value': vuln_counts,
                'penalty_applied': penalty,
                'weights': {
                    'critical': vu["critical_weight"], 'high': vu["high_weight"],
                    'medium': vu["medium_weight"], 'low': vu["low_weight"], 'none': vu["none_weight"]
                },
                'max_penalty': vu["max_penalty"]
            }

    final = 0.0
    if denom > 0:
        final = max(0.0, (raw_score / denom) * 100.0)
    return final, abandoned, breakdown

def get_risk_level(score):
    if score >= 80:
        return "Very Low Risk"
    if score >= 60:
        return "Low Risk"
    if score >= 40:
        return "Medium Risk"
    if score >= 20:
        return "High Risk"
    return "Critical Risk"

# ---------------------------- Main audit -------------------------------------

def audit_repository(owner, repo, verify_ssl, output_file="repo_audit.json",
                     max_commits=500, fail_below=None, config=None,
                     no_deps=False):
    if config is None:
        config = load_config()
    print(f"🔍 Auditing {owner}/{repo}...")

    info = get_repo_info(owner, repo, verify_ssl)
    issues = get_issues_count(owner, repo, verify_ssl)
    last_commit = get_last_commit_date(owner, repo, verify_ssl)
    dev_count = get_active_developers(owner, repo, verify_ssl)
    policy = has_security_policy(owner, repo, verify_ssl)
    has_any_issues = (issues['open'] + issues['closed']) > 0
    signed, sampled = count_signed_commits(owner, repo, verify_ssl, max_commits)

    # Dependency graph / vulnerabilities (optional)
    dep_enabled = None
    dep_count = None
    vuln_counts = None
    alerts_total = None
    if not no_deps:
        dep_enabled, sbom = get_repo_sbom(owner, repo, verify_ssl)
        dep_count = parse_spdx_dependency_count(sbom)
        _, vuln_counts = get_dependabot_alerts(owner, repo, verify_ssl)
        alerts_total = sum(vuln_counts.values()) if vuln_counts else None

    score, abandoned, breakdown = score_repo(
        last_commit,
        dev_count,
        info['license'],
        policy,
        info['language'],
        has_any_issues,
        issues,
        signed,
        sampled,
        dep_enabled,
        vuln_counts,
        config
    )
    risk = get_risk_level(score)

    if abandoned:
        print("⚠️ Warning: Repository appears abandoned (>365 days since last commit)")

    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repository": info['name'],
        "archived": info.get("archived", False),
        "disabled": info.get("disabled", False),

        "last_commit_date": last_commit,
        "active_developers_last_90_days": dev_count,
        "license": info['license'],
        "security_policy": policy,
        "language": info['language'],

        "issue_tracking_enabled": info['issue_tracking_enabled'],
        "has_open_or_closed_issues": has_any_issues,
        "issue_count_open": issues['open'],
        "issue_count_closed": issues['closed'],
        "issue_count_total": issues['open'] + issues['closed'],

        "abandoned": abandoned,

        "signed_commits": signed,
        "total_commits_sampled": sampled,
        "signed_commit_percentage": round((signed / sampled) * 100, 2) if sampled else None,

        "dependency_analysis_enabled": dep_enabled if dep_enabled is not None else None,
        "dependency_count": dep_count if dep_count is not None else None,
        "dependabot_open_alerts_total": alerts_total if alerts_total is not None else None,
        "dependabot_open_alerts_by_severity": vuln_counts if vuln_counts is not None else None,

        "trust_score": score,
        "risk_level": risk
    }

    print(json.dumps(result, indent=4))
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4)
    print(f"✅ Audit saved to {output_file}")

    print("\n📊 Score Breakdown Explanation:")
    for crit, det in breakdown.items():
        thresholds = det.get('threshold') or det.get('thresholds') or det.get('weights')
        print(f"- {crit}: score {det['score']:+} | value: {det.get('value')} | thresholds/rules: {thresholds}")

    if fail_below is not None:
        try:
            threshold = float(fail_below)
        except ValueError:
            print(f"❌ Invalid --fail-below value: {fail_below}. Expected a number.")
            sys.exit(2)

        if threshold < 0 or threshold > 100:
            print(f"⚠️ --fail-below value {threshold} is outside 0–100. Proceeding anyway.")

        if score < threshold:
            print(f"❌ Trust score {score:.2f} is below threshold {threshold}. Exiting with failure.")
            sys.exit(1)
        else:
            print(f"✅ Trust score {score:.2f} meets threshold {threshold}.")

# ---------------------------- CLI --------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Audit a GitHub repo with configurable scoring (INI). Includes optional dependency & vulnerability checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("owner", nargs="?", help="GitHub repository owner (e.g. 'octocat')")
    parser.add_argument("repo", nargs="?", help="GitHub repository name (e.g. 'Hello-World')")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--output", default="repo_audit.json",
                        help="Output file for audit results (default: repo_audit.json)")
    parser.add_argument("--max-commits", type=int, default=500,
                        help="Maximum commits to check for signing (default: 500)")
    parser.add_argument("--fail-below", type=float,
                        help="Exit with non-zero status if trust score is below this value (0–100)")
    parser.add_argument("--config", help="Path to INI config with scoring parameters")
    parser.add_argument("--write-default-config", metavar="PATH",
                        help="Write a default INI to PATH and exit")
    parser.add_argument("--no-deps", action="store_true",
                        help="Skip dependency analysis and Dependabot vulnerability checks")
    args = parser.parse_args()

    if args.write_default_config:
        write_default_config(args.write_default_config)
        return

    if not args.owner or not args.repo:
        print("❌ Missing required arguments: owner and repo.")
        print("   Tip: use --write-default-config config.ini to generate a template.")
        sys.exit(2)

    verify = not args.skipssl
    if args.skipssl:
        warnings.simplefilter('ignore', InsecureRequestWarning)

    config = load_config(args.config) if args.config else load_config()

    audit_repository(args.owner, args.repo, verify,
                     output_file=args.output,
                     max_commits=args.max_commits,
                     fail_below=args.fail_below,
                     config=config,
                     no_deps=args.no_deps)

if __name__ == '__main__':
    main()
