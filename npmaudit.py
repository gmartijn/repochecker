import requests  
import json  
import sys  
import warnings  
from datetime import datetime, timezone  
from requests.packages.urllib3.exceptions import InsecureRequestWarning  
import semver  
  
warnings.simplefilter('ignore', InsecureRequestWarning)  
  
def print_help():  
    help_message = """  
    Usage: python npm_package_audit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below <score>]  
  
    This script audits an NPM package to evaluate its quality based on various criteria.  
      
    Options:  
    --checkdependencies: Audit dependencies individually.  
    --skipssl: Skip SSL certificate verification.  
    --fail-below <score>: Exit with status 1 if any package scores below the specified threshold.  
    """  
    print(help_message)  
  
def get_npm_package_info(package_name, version=None, verify_ssl=True):  
    url = f"https://registry.npmjs.org/{package_name}"  
    try:  
        r = requests.get(url, verify=verify_ssl)  
        r.raise_for_status()  
        data = r.json()  
  
        all_versions = list(data["versions"].keys())  
        if version is None or version not in all_versions:  
            version = data["dist-tags"]["latest"]  
        version_info = data["versions"][version]  
  
        return {  
            "name": data["name"],  
            "latest_version": version,  
            "last_published": data["time"].get(version, "Unknown"),  
            "license": version_info.get("license", "None"),  
            "maintainers": [m["name"] for m in data.get("maintainers", [])],  
            "repository": version_info.get("repository", {}).get("url", ""),  
            "dependencies": version_info.get("dependencies", {}),  
            "available_versions": all_versions  
        }  
    except Exception as e:  
        print(f"Error retrieving NPM package info for {package_name}: {e}")  
        return None  
  
def resolve_version(version_range, all_versions):  
    try:  
        valid_versions = [v for v in all_versions if not semver.VersionInfo.parse(v).prerelease]  
        valid_versions.sort(key=lambda v: semver.VersionInfo.parse(v))  
        for v in reversed(valid_versions):  
            if semver.match(v, version_range):  
                return v  
    except Exception:  
        pass  
    return None  
  
def get_active_developers(package_info):  
    return len(package_info["maintainers"])  
  
def score_package(last_published, num_devs, license_type):  
    total_criteria = 4  
    score = 0  
    if last_published and last_published != "Unknown":  
        try:  
            published = datetime.strptime(last_published, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)  
        except ValueError:  
            published = datetime.strptime(last_published, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)  
        days_since_last = (datetime.now(timezone.utc) - published).days  
        if days_since_last < 90:  
            score += 1  
    if num_devs >= 3:  
        score += 1  
    if license_type != "None":  
        score += 1  
    if num_devs > 0:  
        score += 1  
    return (score / total_criteria) * 100  
  
def get_risk_level(score):  
    if score >= 80: return "Very Low Risk"  
    elif score >= 60: return "Low Risk"  
    elif score >= 40: return "Medium Risk"  
    elif score >= 20: return "High Risk"  
    else: return "Critical Risk"  
  
def audit_npm_package(package_name, verify_ssl=True, version=None):  
    package_info = get_npm_package_info(package_name, version, verify_ssl)  
    if package_info is None:  
        return None, None  
  
    num_devs = get_active_developers(package_info)  
    trust_score = score_package(package_info["last_published"], num_devs, package_info["license"])  
    risk_level = get_risk_level(trust_score)  
  
    result = {  
        "package": package_info["name"],  
        "version": package_info["latest_version"],  
        "last_published": package_info["last_published"],  
        "active_maintainers": num_devs,  
        "license": package_info["license"],  
        "trust_score": trust_score,  
        "risk_level": risk_level  
    }  
  
    return result, (package_info["dependencies"], package_info["available_versions"])  
  
def audit_dependencies(dependencies, verify_ssl=True, fail_threshold=None, failed_packages=None):  
    results = {}  
    for dep_name, version_range in dependencies.items():  
        dep_info = get_npm_package_info(dep_name, verify_ssl=verify_ssl)  
        if not dep_info:  
            continue  
        resolved_version = resolve_version(version_range, dep_info["available_versions"]) or dep_info["latest_version"]  
        result, _ = audit_npm_package(dep_name, verify_ssl=verify_ssl, version=resolved_version)  
        if result:  
            results[dep_name] = result  
            if fail_threshold is not None and result["trust_score"] < fail_threshold:  
                print(f"❌ Dependency '{dep_name}' score {result['trust_score']} < threshold ({fail_threshold})")  
                failed_packages.append(dep_name)  
    return results  
  
def main(package_name, check_dependencies, verify_ssl=True, fail_threshold=None):  
    print("\n⚠️  Disclaimer: This script evaluates NPM packages based on activity, license, and maintainers. It does not verify vendor reputation.\n")  
  
    failed_packages = []  
  
    main_result, (dependencies, _) = audit_npm_package(package_name, verify_ssl)  
    if main_result is None:  
        print("Package audit failed.")  
        sys.exit(1)  
  
    if fail_threshold is not None and main_result["trust_score"] < fail_threshold:  
        print(f"❌ Main package '{package_name}' score {main_result['trust_score']} < threshold ({fail_threshold})")  
        failed_packages.append(package_name)  
  
    output = {"main_package": main_result}  
    print("\nMain Package Audit Result:")  
    print(json.dumps(main_result, indent=4))  
  
    if check_dependencies and dependencies:  
        dep_results = audit_dependencies(dependencies, verify_ssl, fail_threshold, failed_packages)  
        output["dependencies"] = dep_results  
        print("\nDependencies Audit Results:")  
        print(json.dumps(dep_results, indent=4))  
  
    with open("npm_audit.json", "w") as f:  
        json.dump(output, f, indent=4)  
        print("\nResults written to npm_audit.json")  
  
    if failed_packages:  
        print("\n❌ The following packages failed the trust threshold:")  
        for pkg in failed_packages:  
            print(f"   - {pkg}")  
        sys.exit(1)  
  
if __name__ == "__main__":  
    if len(sys.argv) < 2:  
        print("Usage: python npm_package_audit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below <score>]")  
        print("Type --help for more information.")  
        sys.exit(1)  
  
    if "--help" in sys.argv:  
        print_help()  
        sys.exit(0)  
  
    package = sys.argv[1]  
    check_deps = "--checkdependencies" in sys.argv  
    verify_ssl = not ("--skipssl" in sys.argv)  
  
    try:  
        fail_index = sys.argv.index("--fail-below")  
        fail_threshold = float(sys.argv[fail_index + 1])  
    except (ValueError, IndexError):  
        fail_threshold = None  
  
    main(package, check_deps, verify_ssl, fail_threshold)
