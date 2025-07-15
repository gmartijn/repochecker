import requests  
import json  
import sys  
import warnings  
from datetime import datetime, timezone  
  
# Import timezone explicitly  
# Suppress InsecureRequestWarning  
from requests.packages.urllib3.exceptions import InsecureRequestWarning  
warnings.simplefilter('ignore', InsecureRequestWarning)  
  
# ┌─────────────────────────────────────────────────────────────────────────────┐  
# │                          NPM Package Audit Script                          │  
# │                                                                           │  
# │  Note: This script evaluates NPM packages based on various criteria,      │  
# │  including activity, license, and security policies.                       │  
# │  However, please be aware that it does NOT factor in the reputation        │  
# │  of the vendor or maintainer of the package. Use discretion when          │  
# │  interpreting the results.                                                 │  
# │                                                                           │  
# │  Happy auditing!                                                           │  
# └─────────────────────────────────────────────────────────────────────────────┘  
  
def print_help():  
    help_message = """  
    Usage: python npm_package_audit.py <package_name> [--checkdependencies] [--skipssl]  
  
    This script audits an NPM package to evaluate its quality based on various criteria.  
      
    Algorithm Overview:  
    - The script checks the package's latest version, last published date, license type,   
      and the number of active maintainers.  
    - A trust score is calculated based on:  
      1. The recency of the last published date (within the last 90 days).  
      2. The number of active maintainers (at least 3 for a point).  
      3. Whether the package has a license.  
      4. The presence of maintainers.  
    - The trust score is converted into a percentage and categorized into risk levels:  
      - Very Low Risk: 80% and above  
      - Low Risk: 60% to 79%  
      - Medium Risk: 40% to 59%  
      - High Risk: 20% to 39%  
      - Critical Risk: Below 20%  
  
    Output:  
    The output will show the following information for the audited package:  
    - Package Name  
    - Latest Version  
    - Last Published Date  
    - Number of Active Maintainers  
    - License Type  
    - Trust Score (as a percentage)  
    - Risk Level (based on the trust score)  
  
    The results are also written to a file named 'npm_audit.json' in JSON format.  
  
    Options:  
    --checkdependencies:   
    If this option is included, the script will also audit the dependencies listed in the   
    package and provide a similar output for each of them.  
  
    --skipssl:  
    If this option is included, the script will skip SSL certificate verification when   
    making requests to the NPM registry. By default, SSL checking is enabled.  
  
    Example:  
    To audit a package named 'example-package', skip SSL checks, and check its dependencies:  
    python npm_package_audit.py example-package --skipssl --checkdependencies  
    """  
    print(help_message)  
  
def get_npm_package_info(package_name, verify_ssl=True):  
    url = f"https://registry.npmjs.org/{package_name}"  
    try:  
        r = requests.get(url, verify=verify_ssl)  # SSL verification controlled by the parameter  
        r.raise_for_status()  
        data = r.json()  
        latest_version = data["dist-tags"]["latest"]  
        version_info = data["versions"][latest_version]  
  
        return {  
            "name": data["name"],  
            "latest_version": latest_version,  
            "last_published": data["time"][latest_version],  
            "license": version_info.get("license", "None"),  
            "maintainers": [m["name"] for m in data.get("maintainers", [])],  
            "repository": version_info.get("repository", {}).get("url", ""),  
            "dependencies": version_info.get("dependencies", {})  # Fetch dependencies  
        }  
    except Exception as e:  
        print(f"Error retrieving NPM package info: {e}")  
        return None  
  
def get_active_developers(package_info):  
    return len(package_info["maintainers"])  # Count of maintainers as a proxy  
  
def score_package(last_published, num_devs, license_type):  
    total_criteria = 4  # Adjusted total number of criteria for scoring  
    score = 0  
  
    # Recent publish  
    if last_published:  
        published = datetime.strptime(last_published, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)  
        days_since_last = (datetime.now(timezone.utc) - published).days  
        if days_since_last < 90:  
            score += 1  # 1 point for recent publish  
  
    # Active maintainers  
    if num_devs >= 3:  
        score += 1  # 1 point for enough active maintainers  
  
    # License present  
    if license_type != "None":  
        score += 1  # 1 point for having a license  
  
    # Check for issues (not applicable for NPM)  
    if num_devs > 0:  
        score += 1  # 1 point if there are maintainers  
  
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
  
def audit_npm_package(package_name, verify_ssl=True):  
    # Auditing package information  
    package_info = get_npm_package_info(package_name, verify_ssl)  
    if package_info is None:  
        print("Failed to retrieve package information.")  
        return None, None  # Return None for both values  
  
    num_devs = get_active_developers(package_info)  
    trust_score = score_package(package_info["last_published"], num_devs, package_info["license"])  
    risk_level = get_risk_level(trust_score)  
  
    result = {  
        "package": package_info["name"],  
        "latest_version": package_info["latest_version"],  
        "last_published": package_info["last_published"],  
        "active_maintainers": num_devs,  
        "license": package_info["license"],  
        "trust_score": trust_score,  # Now a percentage  
        "risk_level": risk_level  # Add the qualitative risk level  
    }  
  
    return result, package_info.get("dependencies", {})  # Return both values  
  
def audit_dependencies(dependencies, verify_ssl=True):  
    dependency_results = {}  
    for dep_name in dependencies.keys():  
        dep_result, _ = audit_npm_package(dep_name, verify_ssl)  # Audit each dependency  
        if dep_result:  
            dependency_results[dep_name] = dep_result  
    return dependency_results  
  
def main(package_name, check_dependencies, verify_ssl=True):  
    # Display the disclaimer at the start of the audit  
    print("\n⚠️  Disclaimer: This script evaluates NPM packages based on various criteria,")  
    print("    including activity, license, and security policies.")  
    print("    However, it does NOT factor in the reputation of the vendor or")  
    print("    maintainer of the package. Use discretion when interpreting the results.\n")  
      
    package_result, dependencies = audit_npm_package(package_name, verify_ssl)  
  
    if package_result is None:  # Check if package_result is None  
        print("Auditing failed due to package retrieval issues.")  
        return  
  
    # Prepare results for output  
    output_results = {}  
  
    # Store main package result  
    output_results["main_package"] = package_result  
    print("\nMain Package Audit Result:")  
    print(json.dumps(package_result, indent=4))  
  
    # Audit dependencies if requested  
    if check_dependencies and dependencies:  
        dependency_results = audit_dependencies(dependencies, verify_ssl)  
        output_results["dependencies"] = dependency_results  
        print("\nDependencies Audit Results:")  
        print(json.dumps(dependency_results, indent=4))  
  
    # Write all results to npm_audit.json  
    with open('npm_audit.json', 'w') as json_file:  
        json.dump(output_results, json_file, indent=4)  
        print("\nResults written to npm_audit.json")  
  
if __name__ == "__main__":  
    if len(sys.argv) < 2:  
        print("Usage: python npm_package_audit.py <package_name> [--checkdependencies] [--skipssl]")  
        print("Type --help for more information.")  
        sys.exit(1)  
  
    if sys.argv[1] == "--help":  
        print_help()  
        sys.exit(0)  
  
    package_name = sys.argv[1]  
    check_dependencies = '--checkdependencies' in sys.argv  
    verify_ssl = not ('--skipssl' in sys.argv)  
  
    main(package_name, check_dependencies, verify_ssl)  