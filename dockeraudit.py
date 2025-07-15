import requests  
import json  
import sys  
import os  
from datetime import datetime, timezone  
  
# ┌─────────────────────────────────────────────────────────────────────────────┐  
# │                          Docker Hub Image Audit Script                      │  
# │                                                                           │  
# │  Note: This script evaluates Docker images based on various criteria,      │  
# │  including popularity, activity, and maintenance.                          │  
# │  Use discretion when interpreting the results.                             │  
# │                                                                           │  
# │  Happy auditing!                                                           │  
# └─────────────────────────────────────────────────────────────────────────────┘  
  
# Suppress error messages  
devnull = open(os.devnull, 'w')  
sys.stderr = devnull  
  
DOCKER_HUB_API = "https://hub.docker.com/v2"  
  
def get_docker_image_info(image_name):  
    url = f"https://registry.hub.docker.com/v2/repositories/{image_name}/"  
    try:  
        response = requests.get(url, verify=False)  # Disable SSL verification  
        response.raise_for_status()  
        return response.json()  
    except Exception:  
        return None  
  
def get_owner_info(owner):  
    url = f"{DOCKER_HUB_API}/users/{owner}/"  
    try:  
        response = requests.get(url, verify=False)  # Disable SSL verification  
        response.raise_for_status()  
        return response.json()  
    except Exception:  
        return None  
  
def get_org_info(org_name):  
    url = f"{DOCKER_HUB_API}/orgs/{org_name}/"  
    try:  
        response = requests.get(url, verify=False)  # Disable SSL verification  
        response.raise_for_status()  
        return response.json()  
    except Exception:  
        return None  
  
def get_user_info(username):  
    url = f"{DOCKER_HUB_API}/users/{username}/"  
    r = requests.get(url, verify=False)  # Disable SSL verification  
    if r.status_code == 404:  
        return None  
    r.raise_for_status()  
    return r.json()  
  
def get_repo_count(username):  
    url = f"{DOCKER_HUB_API}/repositories/{username}/?page_size=1"  
    r = requests.get(url, verify=False)  # Disable SSL verification  
    if r.status_code == 404:  
        return 0  
    r.raise_for_status()  
    return r.json().get("count", 0)  
  
def classify_user_type(user_data, repo_count):  
    if not user_data:  
        return "unknown"  
    is_org_like = False  
    # Heuristics  
    if user_data.get("company") or repo_count >= 10:  
        is_org_like = True  
    elif not user_data.get("full_name") and repo_count >= 5:  
        is_org_like = True  
    elif user_data.get("full_name") == "" and user_data.get("is_staff"):  
        is_org_like = True  
    return "organization" if is_org_like else "individual"  
  
def analyze_namespace(namespace):  
    user_info = get_user_info(namespace)  
    repo_count = get_repo_count(namespace)  
    user_type = classify_user_type(user_info, repo_count)  
    return user_type  
  
def get_badge_type(org_info):  
    """Determine the badge type of the organization."""  
    badge = org_info.get("badge", "")  
    if badge == "verified_publisher" or badge == "official_image":  
        return True  
    return False  
  
def evaluate_image(image_info, owner, org_info, user_type):  
    # Calculate scores based on the criteria outlined earlier  
    stars = image_info.get("star_count", 0)  
    last_updated = image_info.get("last_updated")  
    pull_count = image_info.get("pull_count", 0)  
    tags_count = image_info.get("tag_count", 0)  
    is_active = org_info.get("is_active", False) if org_info else False  
    is_signed_or_verified = image_info.get("is_signed", False) or image_info.get("is_verified", False)  
  
    # Initialize score  
    score = 0  
  
    # Stars score  
    score += min(stars / 100 * 20, 20)  
  
    # Last updated score  
    if last_updated:  
        last_updated_date = datetime.strptime(last_updated, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)  
        days_since_update = (datetime.now(timezone.utc) - last_updated_date).days  
        if days_since_update <= 30:  
            score += 20  
        elif days_since_update <= 60:  
            score += 15  
        elif days_since_update <= 90:  
            score += 10  
  
    # Pull count score  
    score += min(pull_count / 1000 * 20, 20)  
  
    # Tags count score  
    score += min(tags_count / 50 * 10, 10)  
  
    # Is active score  
    score += 10 if is_active else 0  
  
    # User type score  
    if user_type == "organization":  
        score += 10  
    elif user_type == "individual":  
        score += 5  
  
    # Is signed or verified score  
    score += 10 if is_signed_or_verified else 0  
  
    # Badge type score  
    if org_info and get_badge_type(org_info):  
        score += 15  # Add extra trust for verified publishers and official images  
  
    # Calculate percentage  
    percentage = (score / 100) * 100  
  
    # Determine trust level  
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
  
    # Prepare result with trust level  
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
        "tags": image_info.get("tags", []),  
        "trust_level": trust_level,  
        "percentage": percentage  
    }  
  
    return result  
  
def audit_repository(owner, repo, output_file="repo_audit.json"):  
    # Display the warning at the start of the audit  
    print("\n⚠️  Note: This script evaluates repositories based on various criteria,")  
    print("    including activity, license, and security policies.")  
    print("    However, it does NOT factor in the reputation of the vendor or")  
    print("    maintainer of the repository. Use discretion when interpreting the results.\n")  
  
def main(image_name):  
    # Display warning for the repository audit  
    owner = image_name.split('/')[0]  # Get the part before the first '/'  
    repo = image_name.split('/')[1] if '/' in image_name else None  
    audit_repository(owner, repo)  
  
    image_info = get_docker_image_info(image_name)  
    if image_info:  
        # Get owner information  
        owner_info = get_owner_info(owner)  
  
        # Get organization information  
        org_info = get_org_info(owner)  # Assuming the owner is the organization name  
  
        # Determine user type  
        user_type = analyze_namespace(owner)  
  
        evaluated_result = evaluate_image(image_info, owner, org_info, user_type)  
  
        # Print summary before detailed result  
        print("\nDocker Image Audit Summary:")  
        print(f"Trust Level: {evaluated_result['trust_level']}")  
        print(f"Percentage: {evaluated_result['percentage']:.2f}%\n")  
  
        # Print detailed result to console  
        print("Docker Image Audit Result:")  
        print(json.dumps(evaluated_result, indent=4))  
  
        # Write result to docker_audit.json  
        try:  
            with open('docker_audit.json', 'w') as json_file:  
                json.dump(evaluated_result, json_file, indent=4)  
                print("\nResults written to docker_audit.json")  
        except Exception:  
            print("An error occurred while writing results to docker_audit.json.")  
  
if __name__ == "__main__":  
    if len(sys.argv) < 2:  
        print("Usage: python docker_image_audit.py <image_name>")  
        sys.exit(1)  
  
    image_name = sys.argv[1]  
    main(image_name)  