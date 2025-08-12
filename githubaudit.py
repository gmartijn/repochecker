import os
import sys
import json
import requests
import argparse
import warnings
from datetime import datetime, timedelta, timezone
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                        GitHub Audit Script                                  │
# │                                                                             │
# │  This script evaluates GitHub repositories based on various criteria,       │
# │  including activity, license, and security policies.                        │
# │  It also flags potentially abandoned repositories and provides a detailed   │
# │  breakdown outside of the JSON output.                                      │
# │                                                                             │
# │  New: --fail-below <N> will exit with a non-zero status if the computed     │
# │  trust score is below N (useful for CI gates).                              │
# │                                                                             │
# │  Note: This does not fully account for vendor/maintainer reputation.        │
# │  Use judgment when interpreting results.                                    │
# │                                                                             │
# │  Happy auditing!                                                            │
# └─────────────────────────────────────────────────────────────────────────────┘

# Suppress insecure SSL warnings if skipping verification
warnings.simplefilter('ignore', InsecureRequestWarning)

# GitHub API token from environment (optional)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("⚠️ Warning: No GITHUB_TOKEN set. You may hit rate limits quickly.")


def check_rate_limit(response):
    if response.status_code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
        reset_ts = int(response.headers.get("X-RateLimit-Reset", 0))
        reset_time = datetime.fromtimestamp(reset_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"❗ GitHub API rate limit reached. Try again after {reset_time}.")
        sys.exit(1)


# Fetch repository metadata
# Guard against missing license object
def get_repo_info(owner, repo, verify_ssl):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        r = requests.get(url, headers=HEADERS, verify=verify_ssl)
        check_rate_limit(r)
        r.raise_for_status()
        data = r.json()
        license_info = data.get("license")
        license_name = license_info.get("name") if license_info else "None"
        return {
            "name": data.get("full_name"),
            "license": license_name,
            "language": data.get("language", "Unknown"),
            "issue_tracking_enabled": data.get("has_issues", False)
        }
    except Exception as e:
        print(f"⚠️ Error fetching repo info: {e}")
        return {"name": f"{owner}/{repo}", "license": "Error", "language": "Unknown", "issue_tracking_enabled": False}


# Count open and closed issues via Search API
def get_issues_count(owner, repo, verify_ssl):
    counts = {"open": 0, "closed": 0}
    base = f"https://api.github.com/search/issues?q=repo:{owner}/{repo}+type:issue"
    for state in ['open', 'closed']:
        try:
            url = f"{base}+state:{state}"
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            if r.status_code == 200:
                counts[state] = r.json().get('total_count', 0)
        except Exception as e:
            print(f"⚠️ Error fetching {state} issues: {e}")
    return counts


# Get date of most recent commit
def get_last_commit_date(owner, repo, verify_ssl):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    try:
        r = requests.get(url, headers=HEADERS, verify=verify_ssl)
        check_rate_limit(r)
        r.raise_for_status()
        commits = r.json()
        if commits:
            return commits[0]['commit']['committer']['date']
    except Exception as e:
        print(f"⚠️ Error fetching commits: {e}")
    return None


# Count unique authors in last N days
def get_active_developers(owner, repo, verify_ssl, days=90):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace('+00:00', 'Z')
    devs = set()
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?since={since}&per_page=100&page={page}"
        try:
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            r.raise_for_status()
            commits = r.json()
            if not commits:
                break
            for c in commits:
                author = c.get('author')
                if author and author.get('login'):
                    devs.add(author['login'])
            page += 1
        except Exception as e:
            print(f"⚠️ Error fetching active developers: {e}")
            break
    return len(devs)


# Check for a SECURITY.md file
def has_security_policy(owner, repo, verify_ssl):
    paths = ['.github/SECURITY.md', 'SECURITY.md', 'docs/SECURITY.md']
    for p in paths:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{p}"
        try:
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            if r.status_code == 200:
                return True
        except:
            continue
    return False


# Sample commits to count GPG-signed ones
def count_signed_commits(owner, repo, verify_ssl, max_commits=500):
    per_page, page = 100, 1
    signed, total = 0, 0
    while total < max_commits:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={per_page}&page={page}"
        try:
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            r.raise_for_status()
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


# Scoring logic with external breakdown
def score_repo(last_commit_date, num_devs, license_type, has_policy,
               language, has_issues, issue_counts,
               signed_commits=0, total_sampled=0):
    total_criteria = 7
    raw_score = 0
    abandoned = False
    breakdown = {}

    # 1) Recent commit
    if last_commit_date:
        last = datetime.strptime(last_commit_date, "%Y-%m-%dT%H:%M:%SZ")
        days = (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).days
        passed = days < 90
        if passed:
            raw_score += 1
        if days > 365:
            abandoned = True
        breakdown['recent_commit'] = {
            'score': 1 if passed else 0,
            'value': days,
            'thresholds': {'good_days': 90, 'abandoned_days': 365}
        }
    else:
        abandoned = True
        breakdown['recent_commit'] = {'score': 0, 'value': None, 'thresholds': {'good_days': 90, 'abandoned_days': 365}}

    # 2) Active developers
    dev_ok = num_devs >= 5
    if dev_ok:
        raw_score += 1
    breakdown['active_devs'] = {'score': 1 if dev_ok else 0, 'value': num_devs, 'threshold': 5}

    # 3) License
    norm = license_type.lower() if license_type else ''
    if 'mit' in norm or 'apache' in norm:
        lic_score = 1
    elif 'gpl' in norm:
        lic_score = 0.5
    elif 'mpl' in norm or 'lgpl' in norm:
        lic_score = 0
    else:
        lic_score = -1
    raw_score += lic_score
    breakdown['license'] = {'score': lic_score, 'value': license_type,
                            'rules': {'MIT/Apache': 1, 'GPL': 0.5, 'MPL/LGPL': 0, 'Other': -1}}

    # 4) Security policy
    if has_policy:
        raw_score += 1
    breakdown['security_policy'] = {'score': 1 if has_policy else 0, 'value': has_policy}

    # 5) Language
    popular = ["Python", "JavaScript", "Go", "Rust", "Swift", "Kotlin", "Java", "C#"]
    lang_ok = language in popular
    if lang_ok:
        raw_score += 1
    breakdown['language'] = {'score': 1 if lang_ok else 0, 'value': language}

    # 6) Issue tracking
    if has_issues:
        raw_score += 1
    breakdown['issue_tracking'] = {'score': 1 if has_issues else 0, 'value': has_issues}

    # 7) Issue resolution
    total_issues = issue_counts['open'] + issue_counts['closed']
    if total_issues > 10:
        ratio = issue_counts['closed'] / total_issues
        res_ok = ratio >= 0.6
        raw_score += 1 if res_ok else -1
        breakdown['issue_resolution'] = {'score': 1 if res_ok else -1,
                                         'value': ratio,
                                         'threshold': 0.6}
    else:
        breakdown['issue_resolution'] = {'score': 0, 'value': total_issues, 'threshold': 10}

    # 8) Signed commits
    if total_sampled > 0:
        total_criteria += 1
        ratio = signed_commits / total_sampled
        sign_ok = ratio > 0.5
        if sign_ok:
            raw_score += 1
        breakdown['signed_commits'] = {'score': 1 if sign_ok else 0,
                                       'value': ratio,
                                       'threshold': 0.5}

    # Normalize to 0–100
    final = max(0, (raw_score / total_criteria) * 100)
    return final, abandoned, breakdown


# Map numeric score to risk level
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


# Main audit function
def audit_repository(owner, repo, verify_ssl, output_file="repo_audit.json", max_commits=500, fail_below=None):
    print(f"🔍 Auditing {owner}/{repo}...")

    info = get_repo_info(owner, repo, verify_ssl)
    issues = get_issues_count(owner, repo, verify_ssl)
    last_commit = get_last_commit_date(owner, repo, verify_ssl)
    dev_count = get_active_developers(owner, repo, verify_ssl)
    policy = has_security_policy(owner, repo, verify_ssl)
    has_any_issues = (issues['open'] + issues['closed']) > 0
    signed, sampled = count_signed_commits(owner, repo, verify_ssl, max_commits)

    score, abandoned, breakdown = score_repo(
        last_commit,
        dev_count,
        info['license'],
        policy,
        info['language'],
        has_any_issues,
        issues,
        signed,
        sampled
    )
    risk = get_risk_level(score)

    if abandoned:
        print("⚠️ Warning: Repository appears abandoned (>365 days since last commit)")

    # JSON output without breakdown
    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repository": info['name'],
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
        "trust_score": score,
        "risk_level": risk
    }

    # Write JSON
    print(json.dumps(result, indent=4))
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=4)
    print(f"✅ Audit saved to {output_file}")

    # External breakdown
    print("\n📊 Score Breakdown Explanation:")
    for crit, det in breakdown.items():
        thresholds = det.get('threshold') or det.get('thresholds') or det.get('rules')
        print(f"- {crit}: score {det['score']:+} | value: {det['value']} | thresholds/rules: {thresholds}")

    # Fail-below logic
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


# CLI entrypoint
def main():
    parser = argparse.ArgumentParser(
        description="Audit a GitHub repository based on activity, license, developers, signed commits, and risk scoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("owner", help="GitHub repository owner (e.g. 'octocat')")
    parser.add_argument("repo", help="GitHub repository name (e.g. 'Hello-World')")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--output", default="repo_audit.json",
                        help="Output file for audit results (default: repo_audit.json)")
    parser.add_argument("--max-commits", type=int, default=500,
                        help="Maximum commits to check for signing (default: 500)")
    parser.add_argument("--fail-below", type=float,
                        help="Exit with non-zero status if trust score is below this value (0–100)")
    args = parser.parse_args()
    verify = not args.skipssl
    if args.skipssl:
        warnings.simplefilter('ignore', InsecureRequestWarning)
    audit_repository(args.owner, args.repo, verify,
                     output_file=args.output,
                     max_commits=args.max_commits,
                     fail_below=args.fail_below)


if __name__ == '__main__':
    main()
