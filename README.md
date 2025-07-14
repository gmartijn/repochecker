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
 

## Explanation of the Output 🤯
 

repository: The full name of the repository (owner/repo).
last_commit_date: The date of the most recent commit to the repository.
active_developers_last_90_days: The number of developers who have contributed in the last 90 days.
license: The license under which the repository is released.
security_policy: Indicates whether a security policy is in place.
language: The primary programming language used in the repository.
has_issues: Indicates if the repository has issues enabled.
issue_count: The number of open issues in the repository.
trust_score: A numerical score representing the trustworthiness of the repository.
risk_level: A qualitative assessment of the risk associated with the repository.


### Disclaimer ⚠️⚛️🪖
 
This script evaluates repositories based on various criteria, including activity, license, and security policies. However, it does NOT take into account the reputation of the vendor or maintainer of the repository. Please use discretion when interpreting the results.

### Contributing 🤝
 
If you'd like to contribute to this project or have suggestions for improvements, feel free to open an issue or submit a pull request!

### Acknowledgements 🙌
 
A special thanks to my colleagues, who always tend to emphasize the importance of checking these aspects! Thank you for keeping us accountable and ensuring we don’t just wing it.

Yes I know i am not verifying SSL, because our friendly neighbourhood proxy does SSL inspection which does not always go well with requests, or i'm too lazy to figure it out.

### Happy auditing! 🎉


