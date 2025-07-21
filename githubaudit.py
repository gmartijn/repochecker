import os
import sys
import json
import requests
import argparse
import warnings
import urllib3
from datetime import datetime, timedelta, timezone
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# ┌─────────────────────────────────────────────────────────────────────────────┐  
# │                        Github Audit Script                                  │  
# │                                                                             │  
# │  This script evaluates Github repositories based on various criteria,       │  
# │  including activity, license, and security policies.                        │  
# │  It also flags potentially abandoned repositories.                          │  
# │                                                                             │  
# │  Note: This does not fully account for vendor/maintainer reputation.        │  
# │  Use judgment when interpreting results.                                    │  
# │                                                                             │  
# │  Happy auditing!                                                            │  
# └─────────────────────────────────────────────────────────────────────────────┘  

warnings.simplefilter('ignore', InsecureRequestWarning)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github+json"
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("⚠️ Warning: No GITHUB_TOKEN set. You may hit rate limits quickly.")

def check_rate_limit(r):
    if r.status_code == 403 and r.headers.get('X-RateLimit-Remaining') == '0':
        reset_time = int(r.headers.get("X-RateLimit-Reset", 0))
        wait_until = datetime.fromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"❗ GitHub API rate limit reached. Try again after {wait_until}.")
        sys.exit(1)

def get_repo_info(owner, repo, verify_ssl):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        r = requests.get(url, headers=HEADERS, verify=verify_ssl)
        check_rate_limit(r)
        r.raise_for_status()
        data = r.json()
        return {
            "name": data["full_name"],
            "license": data["license"]["name"] if data.get("license") else "None",
            "language": data.get("language", "Unknown"),
            "issue_tracking_enabled": data.get("has_issues", False)
        }
    except Exception as e:
        print(f"⚠️ Error fetching repo info: {e}")
        return {"name": f"{owner}/{repo}", "license": "Error", "language": "Unknown", "issue_tracking_enabled": False}

def get_issues_count(owner, repo, verify_ssl):
    base_url = f"https://api.github.com/search/issues?q=repo:{owner}/{repo}+type:issue"
    counts = {"open": 0, "closed": 0}

    try:
        for state in ["open", "closed"]:
            url = f"{base_url}+state:{state}"
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            if r.status_code == 200:
                counts[state] = r.json().get("total_count", 0)
    except Exception as e:
        print(f"⚠️ Error fetching issue count: {e}")

    return counts

def get_last_commit_date(owner, repo, verify_ssl):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    try:
        r = requests.get(url, headers=HEADERS, verify=verify_ssl)
        check_rate_limit(r)
        r.raise_for_status()
        commits = r.json()
        if commits:
            return commits[0]["commit"]["committer"]["date"]
    except Exception as e:
        print(f"⚠️ Error fetching commits: {e}")
    return None

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
                if c.get("author") and c["author"].get("login"):
                    devs.add(c["author"]["login"])
            page += 1
        except Exception as e:
            print(f"⚠️ Error fetching active developers: {e}")
            break
    return len(devs)

def has_security_policy(owner, repo, verify_ssl):
    paths = [".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"]
    for path in paths:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        try:
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            if r.status_code == 200:
                return True
        except:
            pass
    return False

def count_signed_commits(owner, repo, verify_ssl, max_commits=500):
    per_page = 100
    page = 1
    signed_count = 0
    total_checked = 0

    while total_checked < max_commits:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={per_page}&page={page}"
        try:
            r = requests.get(url, headers=HEADERS, verify=verify_ssl)
            check_rate_limit(r)
            r.raise_for_status()
            commits = r.json()

            if not commits:
                break

            for commit in commits:
                if total_checked >= max_commits:
                    break
                verification = commit.get("commit", {}).get("verification", {})
                if verification.get("verified"):
                    signed_count += 1
                total_checked += 1

            page += 1

        except Exception as e:
            print(f"⚠️ Error fetching signed commits (page {page}): {e}")
            break

    return signed_count, total_checked

def score_repo(last_commit_date, num_devs, license_type, has_policy, language,
               has_open_or_closed_issues, issue_counts, signed_commits=0, total_sampled=0):
    total_criteria = 7
    score = 0
    is_abandoned = False

    if last_commit_date:
        last_commit = datetime.strptime(last_commit_date, "%Y-%m-%dT%H:%M:%SZ")
        days_since_commit = (datetime.now(timezone.utc) - last_commit.replace(tzinfo=timezone.utc)).days
        if days_since_commit < 90:
            score += 1
        if days_since_commit > 365:
            is_abandoned = True
    else:
        is_abandoned = True

    if num_devs >= 5:
        score += 1

    license_score = 0
    if license_type:
        normalized = license_type.lower()
        if "mit" in normalized or "apache" in normalized:
            license_score = 1
        elif "gpl" in normalized:
            license_score = 0.5
        elif "mpl" in normalized or "lgpl" in normalized:
            license_score = 0
        else:
            license_score = -1
    score += license_score

    if has_policy:
        score += 1

    if language in ["Python", "JavaScript", "Go", "Rust", "Swift", "Kotlin", "Java", "C#"]:
        score += 1

    if has_open_or_closed_issues:
        score += 1

    issue_count_total = issue_counts["open"] + issue_counts["closed"]
    if issue_count_total > 10:
        closed_ratio = issue_counts["closed"] / issue_count_total
        if closed_ratio >= 0.6:
            score += 1
        else:
            score -= 1

    if total_sampled > 0:
        total_criteria += 1
        if signed_commits / total_sampled > 0.5:
            score += 1

    final_score = max(0, (score / total_criteria) * 100)
    return final_score, is_abandoned

def get_risk_level(score):
    if score >= 80:
        return "Very Low Risk"
    elif score >= 60:
        return "Low Risk"
    elif score >= 40:
        return "Medium Risk"
    elif score >= 20:
        return "High Risk"
    else:
        return "Critical Risk"

def audit_repository(owner, repo, verify_ssl, output_file="repo_audit.json", max_commits=500):
    print(f"\n🔍 Auditing {owner}/{repo}...\n")

    repo_info = get_repo_info(owner, repo, verify_ssl)
    issue_counts = get_issues_count(owner, repo, verify_ssl)
    issue_count_total = issue_counts["open"] + issue_counts["closed"]
    last_commit = get_last_commit_date(owner, repo, verify_ssl)
    num_devs = get_active_developers(owner, repo, verify_ssl)
    policy = has_security_policy(owner, repo, verify_ssl)
    has_open_or_closed_issues = issue_count_total > 0
    signed_commits, total_sampled = count_signed_commits(owner, repo, verify_ssl, max_commits)

    trust_score, is_abandoned = score_repo(
        last_commit, num_devs, repo_info["license"], policy,
        repo_info["language"], has_open_or_closed_issues, issue_counts,
        signed_commits, total_sampled
    )

    risk_level = get_risk_level(trust_score)

    if is_abandoned:
        print("⚠️  Warning: This repository appears to be abandoned (no commits in 12+ months).")

    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repository": repo_info["name"],
        "last_commit_date": last_commit,
        "active_developers_last_90_days": num_devs,
        "license": repo_info["license"],
        "security_policy": policy,
        "language": repo_info["language"],
        "issue_tracking_enabled": repo_info["issue_tracking_enabled"],
        "has_open_or_closed_issues": has_open_or_closed_issues,
        "issue_count_open": issue_counts["open"],
        "issue_count_closed": issue_counts["closed"],
        "issue_count_total": issue_count_total,
        "abandoned": is_abandoned,
        "signed_commits": signed_commits,
        "total_commits_sampled": total_sampled,
        "signed_commit_percentage": round((signed_commits / total_sampled) * 100, 2) if total_sampled > 0 else None,
        "trust_score": trust_score,
        "risk_level": risk_level
    }

    print(json.dumps(result, indent=4))

    with open(output_file, "w") as f:
        json.dump(result, f, indent=4)
    print(f"✅ Audit saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Audit a GitHub repository based on activity, license, developers, signed commits, and risk scoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("owner", help="GitHub repository owner (e.g. 'octocat')")
    parser.add_argument("repo", help="GitHub repository name (e.g. 'Hello-World')")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--output", default="repo_audit.json", help="Output file for audit results (default: repo_audit.json)")
    parser.add_argument("--max-commits", type=int, default=500, help="Maximum number of commits to check for signing (default: 500)")

    args = parser.parse_args()
    verify_ssl = not args.skipssl

    if args.skipssl:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', InsecureRequestWarning)

    audit_repository(args.owner, args.repo, verify_ssl, output_file=args.output, max_commits=args.max_commits)

if __name__ == "__main__":
    main()
