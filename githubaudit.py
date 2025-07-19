import os
import sys
import json
import requests
import warnings
from datetime import datetime, timedelta, timezone


# ┌─────────────────────────────────────────────────────────────────────────────┐  
# │                        Github Audit Script                                  │  
# │                                                                             │  
# │  Note: This script evaluates Github repositories based on various criteria, │  
# │  including activity, license, and security policies.                        │  
# │  However, please be aware that it does NOT 100 % factor in the reputation   │  
# │  of the vendor or maintainer of the repo. Use discretion when               │  
# │  interpreting the results.                                                  │  
# │                                                                             │  
# │  Happy auditing!                                                            │  
# └─────────────────────────────────────────────────────────────────────────────┘  

from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else None
}

def get_repo_info(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        r = requests.get(url, headers=HEADERS, verify=False)
        if r.status_code == 403 and r.headers.get('X-RateLimit-Remaining') == '0':
            print("❗ GitHub API rate limit reached. Use a token or wait.")
            sys.exit(1)
        r.raise_for_status()
        data = r.json()
        language = data.get("language", "Unknown")
        has_issues = data.get("has_issues", False)
        return {
            "name": data["full_name"],
            "license": data["license"]["name"] if data.get("license") else "None",
            "language": language,
            "has_issues": has_issues
        }
    except Exception:
        return {"name": f"{owner}/{repo}", "license": "Error", "language": "Unknown", "has_issues": False}

def get_issues_count(owner, repo):
    count = 0
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/issues?state=all&per_page=100&page={page}"
        r = requests.get(url, headers=HEADERS, verify=False)
        if r.status_code != 200:
            break
        issues = r.json()
        if not issues:
            break
        count += sum(1 for issue in issues if 'pull_request' not in issue)
        page += 1
    return count

def get_last_commit_date(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    try:
        r = requests.get(url, headers=HEADERS, verify=False)
        r.raise_for_status()
        commits = r.json()
        if not commits:
            return None
        return commits[0]["commit"]["committer"]["date"]
    except Exception:
        return None

def get_active_developers(owner, repo, days=90):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace('+00:00', 'Z')
    devs = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?since={since}&per_page=100&page={page}"
        try:
            r = requests.get(url, headers=HEADERS, verify=False)
            r.raise_for_status()
            commits = r.json()
            if not commits:
                break
            devs.extend([c["commit"]["author"]["email"] for c in commits if c["commit"].get("author")])
            page += 1
        except Exception:
            break
    return len(set(devs))

def has_security_policy(owner, repo):
    possible_paths = [".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"]
    for path in possible_paths:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        r = requests.get(url, headers=HEADERS, verify=False)
        if r.status_code == 200:
            return True
    return False

def score_repo(last_commit_date, num_devs, license_type, has_policy, language, has_issues, issue_count):
    total_criteria = 6
    score = 0

    if last_commit_date:
        last_commit = datetime.strptime(last_commit_date, "%Y-%m-%dT%H:%M:%SZ")
        days_since_last = (datetime.now(timezone.utc) - last_commit.replace(tzinfo=timezone.utc)).days
        if days_since_last < 90:
            score += 1

    if num_devs >= 5:
        score += 1

    if license_type != "None":
        score += 1

    if has_policy:
        score += 1

    modern_languages = ["Python", "JavaScript", "Go", "Rust", "Swift", "Kotlin", "Java", "C#"]
    if language in modern_languages:
        score += 1

    if has_issues:
        score += 1

    if issue_count > 10:
        score -= 1

    return (score / total_criteria) * 100

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

def audit_repository(owner, repo, output_file="repo_audit.json"):
    print("\n⚠️  Note: This script evaluates repositories based on various criteria,")
    print("    including activity, license, and security policies.")
    print("    However, it does NOT factor in the reputation of the vendor or")
    print("    maintainer of the repository. Use discretion when interpreting the results.\n")

    repo_info = get_repo_info(owner, repo)
    issue_count = get_issues_count(owner, repo)
    last_commit = get_last_commit_date(owner, repo)
    num_devs = get_active_developers(owner, repo)
    policy = has_security_policy(owner, repo)
    trust_score = score_repo(last_commit, num_devs, repo_info["license"], policy, repo_info["language"], repo_info["has_issues"], issue_count)
    risk_level = get_risk_level(trust_score)

    result = {
        "repository": repo_info["name"],
        "last_commit_date": last_commit,
        "active_developers_last_90_days": num_devs,
        "license": repo_info["license"],
        "security_policy": policy,
        "language": repo_info["language"],
        "has_issues": repo_info["has_issues"],
        "issue_count": issue_count,
        "trust_score": trust_score,
        "risk_level": risk_level
    }

    print(json.dumps(result, indent=4))

    with open(output_file, "w") as f:
        json.dump(result, f, indent=4)
    print(f"Audit saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python github_repo_audit.py <owner> <repo>")
        sys.exit(1)
    audit_repository(sys.argv[1], sys.argv[2])
