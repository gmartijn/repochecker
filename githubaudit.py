import requests  
import json  
import sys  
import warnings  
from datetime import datetime, timedelta, timezone  
  
# Suppress InsecureRequestWarning  
from requests.packages.urllib3.exceptions import InsecureRequestWarning  
warnings.simplefilter('ignore', InsecureRequestWarning)  
  
# ┌─────────────────────────────────────────────────────────────────────────────┐  
# │                        GitHub Repository Audit Script                      │  
# │                                                                           │  
# │  Note: This script evaluates repositories based on various criteria,      │  
# │  including activity, license, and security policies.                       │  
# │  However, please be aware that it does NOT factor in the reputation        │  
# │  of the vendor or maintainer of the repository. Use discretion when       │  
# │  interpreting the results.                                                 │  
# │                                                                           │  
# │  Happy auditing!                                                           │  
# └─────────────────────────────────────────────────────────────────────────────┘  
  
# Insert your GitHub personal access token here (optional but recommended)  
GITHUB_TOKEN = ''  
HEADERS = {  
    "Accept": "application/vnd.github+json",  
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else None  
}  
  
def get_repo_info(owner, repo):  
    url = f"https://api.github.com/repos/{owner}/{repo}"  
    try:  
        r = requests.get(url, headers=HEADERS, verify=False)  # SSL verification disabled  
        r.raise_for_status()  
        data = r.json()  
        language = data.get("language", "Unknown")  
        has_issues = data.get("has_issues", False)  
        return {  
            "name": data["full_name"],  
            "license": data["license"]["name"] if data["license"] else "None",  
            "language": language,  
            "has_issues": has_issues  
        }  
    except Exception:  
        return {"name": f"{owner}/{repo}", "license": "Error", "language": "Unknown", "has_issues": False}  
  
def get_issues_count(owner, repo):  
    url = f"https://api.github.com/repos/{owner}/{repo}/issues?state=all"  
    try:  
        r = requests.get(url, headers=HEADERS, verify=False)  # SSL verification disabled  
        r.raise_for_status()  
        issues = r.json()  
        # Count issues, excluding pull requests (which are also returned by this endpoint)  
        issue_count = sum(1 for issue in issues if 'pull_request' not in issue)  
        return issue_count  
    except Exception:  
        return 0  
  
def get_last_commit_date(owner, repo):  
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"  
    try:  
        r = requests.get(url, headers=HEADERS, verify=False)  # SSL verification disabled  
        r.raise_for_status()  
        commits = r.json()  
        if not commits:  
            return None  
        last_commit_date = commits[0]["commit"]["committer"]["date"]  
        return last_commit_date  
    except Exception:  
        return None  
  
def get_active_developers(owner, repo, days=90):  
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace('+00:00', 'Z')  
    devs = []  
    page = 1  
    url = f"https://api.github.com/repos/{owner}/{repo}/commits?since={since}"  
  
    while True:  
        try:  
            r = requests.get(f"{url}&page={page}", headers=HEADERS, verify=False)  # SSL verification disabled  
            r.raise_for_status()  
            commits = r.json()  
            if not commits:  
                break  
            devs.extend([c["commit"]["author"]["email"] for c in commits if c["commit"]["author"]])  
            page += 1  
        except Exception:  
            break  
  
    unique_devs = len(set(devs))  
    return unique_devs  
  
def has_security_policy(owner, repo):  
    url = f"https://api.github.com/repos/{owner}/{repo}/security/policy"  
    try:  
        r = requests.get(url, headers=HEADERS, verify=False)  # SSL verification disabled  
        return r.status_code == 200  
    except Exception:  
        return False  
  
def score_repo(last_commit_date, num_devs, license_type, has_policy, language, has_issues, issue_count):  
    total_criteria = 6  # Total number of criteria for scoring  
    score = 0  
  
    # Recent commits  
    if last_commit_date:  
        last_commit = datetime.strptime(last_commit_date, "%Y-%m-%dT%H:%M:%SZ")  
        days_since_last = (datetime.now(timezone.utc) - last_commit.replace(tzinfo=timezone.utc)).days  
        if days_since_last < 90:  
            score += 1  # 1 point for recent commits  
  
    # Active developers  
    if num_devs >= 5:  
        score += 1  # 1 point for enough active devs  
  
    # License present  
    if license_type != "None":  
        score += 1  # 1 point for having a license  
  
    # Security policy present  
    if has_policy:  
        score += 1  # 1 point for having a security policy  
  
    # Language check  
    modern_languages = ["Python", "JavaScript", "Go", "Rust", "Swift", "Kotlin", "Java", "C#"]  
    os_relevant_languages = ["Shell", "Bash", "PowerShell", "Perl", "Ruby"]  
  
    if language in modern_languages:  
        score += 1  # 1 point for modern languages  
    elif language in os_relevant_languages:  
        score -= 1  # -1 point for OS relevant languages  
  
    # Check for issues  
    if has_issues:  
        score += 1  # 1 point if issues are enabled  
  
    # Add penalty for a high number of issues  
    if issue_count > 10:  # Example threshold  
        score -= 1  # -1 point for too many issues  
  
    # Calculate percentage score  
    percentage_score = (score / total_criteria) * 100  
    return percentage_score  
  
def get_risk_level(percentage_score):  
    if percentage_score >= 80:  
        return "Very Low Risk"  
    elif percentage_score >= 60:  
        return "Low Risk"  
    elif percentage_score >= 40:  
        return "Medium Risk"  
    elif percentage_score >= 20:  
        return "High Risk"  
    else:  
        return "Critical Risk"  
  
def audit_repository(owner, repo, output_file="repo_audit.json"):  
    # Display the warning at the start of the audit  
    print("\n⚠️  Note: This script evaluates repositories based on various criteria,")  
    print("    including activity, license, and security policies.")  
    print("    However, it does NOT factor in the reputation of the vendor or")  
    print("    maintainer of the repository. Use discretion when interpreting the results.\n")  
  
    repo_info = get_repo_info(owner, repo)  
    issue_count = get_issues_count(owner, repo)  # Get the count of issues  
    last_commit = get_last_commit_date(owner, repo)  
    num_devs = get_active_developers(owner, repo)  
    policy = has_security_policy(owner, repo)  
    trust_score = score_repo(last_commit, num_devs, repo_info["license"], policy, repo_info["language"], repo_info["has_issues"], issue_count)  
    risk_level = get_risk_level(trust_score)  # Get the qualitative risk level  
  
    result = {  
        "repository": repo_info["name"],  
        "last_commit_date": last_commit,  
        "active_developers_last_90_days": num_devs,  
        "license": repo_info["license"],  
        "security_policy": policy,  
        "language": repo_info["language"],  
        "has_issues": repo_info["has_issues"],  
        "issue_count": issue_count,  # Add the issue count to the result  
        "trust_score": trust_score,  # Now a percentage  
        "risk_level": risk_level  # Add the qualitative risk level  
    }  
  
    # Print the result to the terminal  
    print(json.dumps(result, indent=4))  
  
    # Save the result to a JSON file  
    with open(output_file, "w") as f:  
        json.dump(result, f, indent=4)  
    print(f"Audit saved to {output_file}")  
  
if __name__ == "__main__":  
    if len(sys.argv) < 3:  
        print("Usage: python github_repo_audit.py <owner> <repo>")  
        sys.exit(1)  
    owner = sys.argv[1]  
    repo = sys.argv[2]  
    audit_repository(owner, repo)  