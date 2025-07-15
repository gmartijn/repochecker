# GitHub Repository Audit Script 🚀  
  
Welcome to the **GitHub Repository Audit Script**! This tool is designed to evaluate GitHub repositories based on various criteria, such as activity, license, and security policies.   
  
## Why This Script? 🤔  
  
You might be asking, "Why do I need this script?" Let's face it: we all have that one colleague who *loves* to check repos for quality and security. You know, the one who brings up the importance of audits at every team meeting? This script is here to save the day! Impress your team by automating the auditing process and avoid endless discussions about "best practices."  
  
*“Have you checked the security policy?”*    
*“Did you look at the last commit date?”*    
  
With this script, you can confidently respond, “Yes, I have!” while quietly thanking yourself for using this awesome tool. 🤦‍♂️
  
## Features ✨  
  
- **Repository Info:** Get detailed information about the repository, including its license and primary language.    
- **Issue Count:** Count the open issues in the repo (because some issues may never get fixed).    
- **Last Commit Date:** Find out how long it’s been since the last contribution to the repo.    
- **Active Developers:** Count how many contributors have been active in the last 90 days.    
- **Security Policy Check:** Verify if the repo has a security policy in place for added peace of mind.    
- **Trust Score:** Obtain a percentage score that evaluates the trustworthiness of the repository.    
- **Risk Level:** Get a qualitative risk indicator ranging from “Critical Risk” to “Very Low Risk.” Perfect for making dramatic assessments!  
  
## Getting Started 🛠️  
  
### Prerequisites  
  
Ensure you have Python installed (3.6 or higher is recommended). You can download it from [python.org](https://www.python.org/downloads/).  
  
### Installation  
  
1. Clone the repository:  
   ```bash  
   git clone https://github.com/gmartijn/repochecker.git or use the 🔨 tool of your choice.
   cd repochecker 
2. Install the required dependencies:
   ```bash  
   pip install -r requirements.txt  
 

## Usage 🔨
 
Run the script with the following command:

1. EXAMPLE
   ```bash  
    python githubaudit.py <owner> <repo>  
 


### Sample Output

1. So lets just say you want to check out https://github.com/octocat/hello-world
    ```bash
    python githubaudit.py octocat hello-world 



After running the command, you might see an output like this:

Output of the CLI

{  
    "repository": "octocat/Hello-World",  
    "last_commit_date": "2023-01-15T12:34:56Z",  
    "active_developers_last_90_days": 3,  
    "license": "MIT",  
    "security_policy": true,  
    "language": "Ruby",  
    "has_issues": true,  
    "issue_count": 5,  
    "trust_score": 75.0,  
    "risk_level": "Low Risk"  
}  
 
# Trust Score Calculation Algorithm 📊  
  
The **trust_score** is a numerical representation of the trustworthiness of a GitHub repository. The score is calculated based on several factors, each contributing to the overall score in a weighted manner. Below are the components used in the calculation:  
  
## Components of Trust Score 🤓
  
1. **Repository Activity (30%)**  
   - **Criteria**: Number of commits in the last 90 days.  
   - **Scoring**:   
     - 0 commits: 0 points  
     - 1-5 commits: 25 points  
     - 6-15 commits: 50 points  
     - 16+ commits: 100 points  
  
2. **Active Developers (20%)**  
   - **Criteria**: Number of unique contributors in the last 90 days.  
   - **Scoring**:  
     - 0 contributors: 0 points  
     - 1 contributor: 20 points  
     - 2-3 contributors: 40 points  
     - 4+ contributors: 100 points  
  
3. **Issue Resolution Rate (20%)**  
   - **Criteria**: Percentage of closed issues to total issues.  
   - **Scoring**:  
     - 0%: 0 points  
     - 1-50%: 50 points  
     - 51-100%: 100 points  
  
4. **License Type (15%)**  
   - **Criteria**: Type of license used (open-source vs. proprietary).  
   - **Scoring**:  
     - Proprietary: 0 points  
     - Open-source (e.g., MIT, Apache 2.0): 100 points  
  
5. **Security Policy (15%)**  
   - **Criteria**: Whether the repository has a security policy.  
   - **Scoring**:  
     - No security policy: 0 points  
     - Security policy present: 100 points  
  
## Trust Score Calculation Formula  🧑‍🔬
  
The trust score is calculated using the following formula:  

trust_score = (activity_score * 0.30) + (developer_score * 0.20) + (issue_resolution_score * 0.20) + (license_score * 0.15) + (security_score * 0.15)

  
### Example Calculation  👈
  
Assume the following scores were derived from the criteria above:  
  
- Repository Activity Score: 75 points  
- Active Developers Score: 40 points  
- Issue Resolution Rate Score: 100 points  
- License Score: 100 points  
- Security Policy Score: 100 points  
  
Using the formula:  

trust_score = (75 * 0.30) + (40 * 0.20) + (100 * 0.20) + (100 * 0.15) + (100 * 0.15)
trust_score = 22.5 + 8 + 20 + 15 + 15 = 80.5 

  
Thus, the calculated **trust_score** would be **80.5**.  
  
## Conclusion  🏁
  
The trust_score provides a quantitative measure of a repository's reliability and activity. Higher scores indicate more active, well-maintained, and secure repositories, making them more trustworthy for use in projects.  

### Disclaimer ⚠️⚛️🪖
 
This script evaluates repositories based on various criteria, including activity, license, and security policies. However, it does NOT take into account the reputation of the vendor or maintainer of the repository. Please use discretion when interpreting the results.

### Contributing 🤝
 
If you'd like to contribute to this project or have suggestions for improvements, feel free to open an issue or submit a pull request!

### Acknowledgements 🙌
 
A special thanks to my colleagues, who always tend to emphasize the importance of checking these aspects! Thank you for keeping us accountable and ensuring we don’t just wing it.

Yes I know i am not verifying SSL, because our friendly neighbourhood proxy does SSL inspection which does not always go well with requests, or i'm too lazy to figure it out.

### Happy auditing! 🎉


