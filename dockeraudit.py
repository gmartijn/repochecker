import requests
import json
import sys
import argparse
import urllib3
from datetime import datetime, timezone
from typing import Optional

DOCKER_HUB_API = "https://hub.docker.com/v2"
HTTP_TIMEOUT = 15  # seconds


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                        Docker Audit Scssssript                                  │
# │                                                                             │
# │  Note: This script evaluates Docker images based on various criteria,       │
# │  including activity, license, and security policies.                        │
# │  However, please be aware that it does NOT 100 % factor in the reputation   │
# │  of the vendor or maintainer of the image. Use discretion when              │
# │  interpreting the results.                                                  │
# │                                                                             │
# │  Happy auditing!                                                            │
# └─────────────────────────────────────────────────────────────────────────────┘

def get_docker_image_info(image_name, verify=True):
    url = f"https://registry.hub.docker.com/v2/repositories/{image_name}/"
    try:
        response = requests.get(url, verify=verify, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def get_user_info(username, verify=True):
    url = f"{DOCKER_HUB_API}/users/{username}/"
    try:
        r = requests.get(url, verify=verify, timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def get_org_info(org_name, verify=True):
    url = f"{DOCKER_HUB_API}/orgs/{org_name}/"
    try:
        response = requests.get(url, verify=verify, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def get_repo_count(username, verify=True):
    url = f"{DOCKER_HUB_API}/repositories/{username}/?page_size=1"
    try:
        r = requests.get(url, verify=verify, timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            return 0
        r.raise_for_status()
        return r.json().get("count", 0)
    except Exception:
        return 0


def classify_user_type(user_data, repo_count):
    if not user_data:
        return "unknown"
    if user_data.get("company") or repo_count >= 10:
        return "organization"
    if not user_data.get("full_name") and repo_count >= 5:
        return "organization"
    if user_data.get("full_name") == "" and user_data.get("is_staff"):
        return "organization"
    return "individual"


def analyze_namespace(namespace, verify=True):
    user_info = get_user_info(namespace, verify=verify)
    repo_count = get_repo_count(namespace, verify=verify)
    return classify_user_type(user_info, repo_count)


def get_badge_type(org_info):
    """
    Returns True if the org has a 'verified_publisher' or 'official_image' badge.
    """
    badge = org_info.get("badge", "")
    return badge in ("verified_publisher", "official_image")


def _parse_iso8601(dt: Optional[str]) -> Optional[datetime]:
    if not dt:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(dt, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def evaluate_image(image_info, owner, org_info, user_type, show_details=False):
    stars = image_info.get("star_count", 0) or 0
    last_updated = image_info.get("last_updated")
    pull_count = image_info.get("pull_count", 0) or 0
    tags_count = image_info.get("tag_count", 0) or 0
    is_active = org_info.get("is_active", False) if org_info else False
    is_signed_or_verified = bool(image_info.get("is_signed") or image_info.get("is_verified"))

    score = 0.0
    details = []

    # Stars: 0.2 pts per star, max 20 (i.e., maxed at 100 stars)
    star_score = min(stars * 0.2, 20.0)
    score += star_score
    if show_details:
        details.append(f"Stars score: {star_score:.2f} (from {stars} stars)")

    # Last updated score
    update_score = 0
    last_dt = _parse_iso8601(last_updated)
    if last_dt:
        days_since_update = (datetime.now(timezone.utc) - last_dt).days
        if days_since_update <= 30:
            update_score = 20
        elif days_since_update <= 60:
            update_score = 15
        elif days_since_update <= 90:
            update_score = 10
        if show_details:
            details.append(f"Update score: {update_score} (last updated {days_since_update} days ago)")
    score += update_score

    # Pulls: 0.02 pts per 1,000 pulls, max 20 → 1,000,000 pulls to max out
    pull_score = min((pull_count / 1000.0) * 0.02, 20.0)
    score += pull_score
    if show_details:
        details.append(f"Pull count score: {pull_score:.2f} (from {pull_count} pulls)")

    # Tags: 0.2 pts per tag, max 10 (capped at 50 tags)
    tag_score = min(tags_count * 0.2, 10.0)
    score += tag_score
    if show_details:
        details.append(f"Tags score: {tag_score:.2f} (from {tags_count} tags)")

    # Active organization
    active_score = 10 if is_active else 0
    score += active_score
    if show_details:
        details.append(f"Organization active score: {active_score}")

    # User type
    user_score = 10 if user_type == "organization" else 5 if user_type == "individual" else 0
    score += user_score
    if show_details:
        details.append(f"User type score ({user_type}): {user_score}")

    # Signed or verified
    signed_score = 10 if is_signed_or_verified else 0
    score += signed_score
    if show_details:
        details.append(f"Signed/verified score: {signed_score}")

    # Badge type score
    badge_score = 15 if org_info and get_badge_type(org_info) else 0
    score += badge_score
    if show_details:
        details.append(f"Badge score: {badge_score}")

    percentage = round(score, 2)
    if percentage >= 90:
        trust_level = "Critical"
    elif percentage >= 75:
        trust_level = "High"
    elif percentage >= 50:
        trust_level = "Medium"
    elif percentage >= 25:
        trust_level = "Low"
    else:
        trust_level = "Very Low"

    result = {
        "name": image_info.get("name"),
        "description": image_info.get("description", "No description available") or "No description available",
        "stars": stars,
        "tags_count": tags_count,
        "last_updated": last_updated,
        "pull_count": pull_count,
        "owner": owner,
        "organization": org_info.get("full_name") if org_info else "No organization info available",
        "profile_url": org_info.get("profile_url") if org_info else None,
        "badge": org_info.get("badge") if org_info else None,
        "is_active": is_active,
        "user_type": user_type,
        "trust_level": trust_level,
        "percentage": percentage
    }

    if show_details:
        result["score_breakdown"] = details

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Docker Image Trust Auditor – Evaluate the trustworthiness of Docker Hub images.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
TRUST SCORE CALCULATION:

The total score is out of 100 and based on:

  • Stars: Up to 20 points (0.2 pts per star, max 100 stars)
  • Last Update:
      - ≤30 days: +20 pts
      - ≤60 days: +15 pts
      - ≤90 days: +10 pts
  • Pulls: Up to 20 points (0.02 pts per 1,000 pulls)
  • Tags: Up to 10 points (0.2 pts per tag, max 50 tags)
  • Active Organization: +10 pts
  • User Type:
      - Organization: +10 pts
      - Individual: +5 pts
  • Signed/Verified Image: +10 pts
  • Verified Publisher/Official Badge: +15 pts

TRUST LEVELS:

  • ≥90  → Critical
  • ≥75  → High
  • ≥50  → Medium
  • ≥25  → Low
  • <25  → Very Low

Example usage:
  python docker_image_audit.py nginx
  python docker_image_audit.py bitnami/postgresql --score-details --skipssl
  python docker_image_audit.py nginx --fail-below 80
        """
    )

    parser.add_argument("image_name", help="Name of the Docker image (e.g., nginx or library/ubuntu)")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification.")
    parser.add_argument("--json", action="store_true", help="Only write to docker_audit.json without console output.")
    parser.add_argument("--score-details", action="store_true", help="Include a breakdown of score components.")
    parser.add_argument(
        "--fail-below", type=float, metavar="SCORE",
        help="Exit with status 1 if the trust score is below this threshold."
    )

    args = parser.parse_args()

    # Conditionally suppress SSL warnings
    if args.skipssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    verify_ssl = not args.skipssl

    image_name = args.image_name
    if '/' not in image_name:
        image_name = f"library/{image_name}"

    owner = image_name.split('/')[0]

    if not args.json:
        print("🔎 Auditing Docker image:", image_name)
        print("⚠️  This tool evaluates trust based on metadata only.")
        print("   It does not evaluate code quality or image contents. Use discretion.\n")

    image_info = get_docker_image_info(image_name, verify=verify_ssl)
    if not image_info:
        print("❌ Failed to fetch image info.")
        sys.exit(1)

    org_info = get_org_info(owner, verify=verify_ssl)
    user_type = analyze_namespace(owner, verify=verify_ssl)
    evaluated = evaluate_image(image_info, owner, org_info, user_type, show_details=args.score_details)

    if not args.json:
        print("\nDocker Image Audit Summary:")
        print(f"Trust Level: {evaluated['trust_level']}")
        print(f"Score: {evaluated['percentage']:.2f}%")
        print("\nFull Audit Result:")
        print(json.dumps(evaluated, indent=4))

    try:
        with open("docker_audit.json", "w") as f:
            json.dump(evaluated, f, indent=4)
        if not args.json:
            print("\n✅ Results written to docker_audit.json")
    except Exception:
        print("❌ Failed to write docker_audit.json")

    # --- Fail-below logic ---
    if args.fail_below is not None:
        if evaluated["percentage"] < args.fail_below:
            if not args.json:
                print(f"\n❌ Score {evaluated['percentage']:.2f}% is below threshold {args.fail_below}%.")
            sys.exit(1)
        else:
            if not args.json:
                print(f"\n✅ Score {evaluated['percentage']:.2f}% meets or exceeds threshold {args.fail_below}%.")
            sys.exit(0)


if __name__ == "__main__":
    main()
