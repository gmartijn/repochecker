import requests
import json
import sys
import argparse
from datetime import datetime, timezone

DOCKER_HUB_API = "https://hub.docker.com/v2"

def get_docker_image_info(image_name, verify=True):
    url = f"https://registry.hub.docker.com/v2/repositories/{image_name}/"
    try:
        response = requests.get(url, verify=verify)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None

def get_user_info(username, verify=True):
    url = f"{DOCKER_HUB_API}/users/{username}/"
    r = requests.get(url, verify=verify)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()

def get_org_info(org_name, verify=True):
    url = f"{DOCKER_HUB_API}/orgs/{org_name}/"
    try:
        response = requests.get(url, verify=verify)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None

def get_repo_count(username, verify=True):
    url = f"{DOCKER_HUB_API}/repositories/{username}/?page_size=1"
    r = requests.get(url, verify=verify)
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    return r.json().get("count", 0)

def classify_user_type(user_data, repo_count):
    if not user_data:
        return "unknown"
    is_org_like = False
    if user_data.get("company") or repo_count >= 10:
        is_org_like = True
    elif not user_data.get("full_name") and repo_count >= 5:
        is_org_like = True
    elif user_data.get("full_name") == "" and user_data.get("is_staff"):
        is_org_like = True
    return "organization" if is_org_like else "individual"

def analyze_namespace(namespace, verify=True):
    user_info = get_user_info(namespace, verify=verify)
    repo_count = get_repo_count(namespace, verify=verify)
    user_type = classify_user_type(user_info, repo_count)
    return user_type

def get_badge_type(org_info):
    badge = org_info.get("badge", "")
    return badge in ("verified_publisher", "official_image")

def evaluate_image(image_info, owner, org_info, user_type, show_details=False):
    stars = image_info.get("star_count", 0)
    last_updated = image_info.get("last_updated")
    pull_count = image_info.get("pull_count", 0)
    tags_count = image_info.get("tag_count", 0)
    is_active = org_info.get("is_active", False) if org_info else False
    is_signed_or_verified = image_info.get("is_signed", False) or image_info.get("is_verified", False)

    score = 0
    details = []

    # Stars
    stars_score = min(stars / 100 * 20, 20)
    score += stars_score
    if show_details: details.append(f"Stars score: {stars_score:.2f}")

    # Last updated
    if last_updated:
        last_updated_date = datetime.strptime(last_updated, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        days_since_update = (datetime.now(timezone.utc) - last_updated_date).days
        if days_since_update <= 30:
            update_score = 20
        elif days_since_update <= 60:
            update_score = 15
        elif days_since_update <= 90:
            update_score = 10
        else:
            update_score = 0
        score += update_score
        if show_details: details.append(f"Update score: {update_score} (last updated {days_since_update} days ago)")

    # Pull count
    pull_score = min(pull_count / 1000 * 20, 20)
    score += pull_score
    if show_details: details.append(f"Pull count score: {pull_score:.2f}")

    # Tags
    tag_score = min(tags_count / 50 * 10, 10)
    score += tag_score
    if show_details: details.append(f"Tags score: {tag_score:.2f}")

    # Active status
    active_score = 10 if is_active else 0
    score += active_score
    if show_details: details.append(f"Org active score: {active_score}")

    # User type
    user_score = 10 if user_type == "organization" else 5 if user_type == "individual" else 0
    score += user_score
    if show_details: details.append(f"User type score ({user_type}): {user_score}")

    # Signed/verified
    signed_score = 10 if is_signed_or_verified else 0
    score += signed_score
    if show_details: details.append(f"Signed/verified score: {signed_score}")

    # Badge type
    badge_score = 15 if org_info and get_badge_type(org_info) else 0
    score += badge_score
    if show_details: details.append(f"Badge score: {badge_score}")

    percentage = score
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
        "description": image_info.get("description", "No description available"),
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
        "percentage": percentage,
    }

    if show_details:
        result["score_breakdown"] = details

    return result

def main():
    parser = argparse.ArgumentParser(description="Audit a Docker image's trustworthiness.")
    parser.add_argument("image_name", help="Name of the Docker image (e.g. library/ubuntu or nginx)")
    parser.add_argument("--skipssl", action="store_true", help="Skip SSL certificate verification.")
    parser.add_argument("--json", action="store_true", help="Output to docker_audit.json only.")
    parser.add_argument("--score-details", action="store_true", help="Print detailed score breakdown.")

    args = parser.parse_args()
    verify_ssl = not args.skipssl

    image_name = args.image_name
    if '/' not in image_name:
        image_name = f"library/{image_name}"

    owner = image_name.split('/')[0]

    print("🔎 Auditing Docker image:", image_name)
    if not args.json:
        print("\n⚠️  This tool does not evaluate code quality or image contents. Use discretion.\n")

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

if __name__ == "__main__":
    main()
