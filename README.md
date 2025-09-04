# Repository Audit Scripts 🚀

Welcome to **Repository Audit Scripts** – the Swiss Army knife for lazy (read: efficient) developers, DevOps gremlins, and security-conscious caffeine addicts. Why manually check things when a script can do it faster, better, and without reading another 400-page compliance doc?

---

## Why These Scripts? 🤔

You know that one teammate who always pipes up in the meeting with, “Did anyone check the license? Are there vulnerabilities? Does this Dockerfile follow best practices?”

This toolkit is how you avoid eye contact and smugly mutter, “Already done.”

Whether you're trying to impress your boss, appease your CI pipeline, or just want to avoid triggering a Friday fire drill, these scripts are your trusty sidekicks. 🧘‍♂️

---

## Features ✨

### `githubaudit.py` – The Repo Investigator You Didn’t Know You Needed 🕵️‍♀️🍸

This script snoops through your GitHub repo like a nosy neighbor with an API key. Think of it as your overly judgmental auditor with strong opinions and a thing for JSON.

#### 💼 What It Actually Does

- **📟 Repo Resume Review:** Checks your repo’s name, license, language, and whether you allow issues.
- **💀 Last Commit Poke Test:** Detects inactivity or abandonment.
- **👷‍♂️ Developer Headcount:** Counts unique committers in the last 90 days (ignores bots).
- **⚖️ License Snooping:** Scores based on license family.
- **🛡️ Security Policy Hunt:** Looks for `SECURITY.md`.
- **💻 Language Bias:** Gives points for popular, modern languages.
- **🐛 Bug Count Check:** Compares open/closed issues for a resolution ratio.
- **✍️ Signed Commit Detection:** Samples commits and checks for GPG-verified signatures.
- **📦 Dependency Analysis (NEW):** Detects if GitHub’s dependency graph is enabled.
- **🕳️ Vulnerability Alerts (NEW):** Pulls open Dependabot alerts and penalizes by severity.
- **📈 Trust Score + Risk Level:** Rolls everything into a neat number and risk label.
- **📝 Configurable Scoring:** All thresholds, weights, popular language list, license scoring, dependency/vulnerability weights are configurable via **INI**.
- **🧪 CI-friendly:** `--fail-below` exits non-zero if the score doesn’t meet your bar.
- **📦 Output:** Saves everything to `repo_audit.json`.
- **🔑 Prefers a GitHub token:** Yes, it *works* without one, but the unauthenticated rate limit is basically training wheels. Enjoy 403s, or set a token like a responsible adult. 😇

#### 🧪 Usage

```bash
python githubaudit.py <owner> <repo>   [--skipssl]   [--output <file>]   [--max-commits N]   [--fail-below SCORE]   [--config path/to/config.ini]   [--write-default-config path/to/new.ini]   [--no-deps]
```

#### 🛠️ Options

| Flag | Description |
|------|-------------|
| `--skipssl` | Skip SSL certificate verification. |
| `--output` | Output file for audit results (default: `repo_audit.json`). |
| `--max-commits` | Number of recent commits to sample for signed-commit check (default: 500). |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value (0–100). Perfect for CI/CD gates. |
| `--config <path>` | Load scoring parameters from an **INI** file. |
| `--write-default-config <path>` | Write a default **INI** with the current built-in parameters and exit. |
| `--no-deps` | Skip dependency graph + Dependabot vulnerability checks (useful if your token lacks `security_events` scope or you just want a faster run). |

---

#### ⚙️ Configuration (INI)

Generate a starter file:

```bash
python githubaudit.py --write-default-config github_audit.defaults.ini
```

Then tweak to taste and run:

```bash
python githubaudit.py octocat Hello-World --config github_audit.defaults.ini
```

**Example `config.ini`:**

```ini
[recent_commit]
good_days = 90
abandoned_days = 365
score = 1

[active_devs]
threshold = 5
score = 1

[license_scores]
mit = 1
apache = 1
gpl = 0.5
mpl = 0
lgpl = 0
other = -1

[security_policy]
score = 1

[language]
popular = Python, JavaScript, Go, Rust, Swift, Kotlin, Java, C#
score = 1

[issue_tracking]
score = 1

[issue_resolution]
min_issues = 10
ratio_threshold = 0.6
score_pass = 1
score_fail = -1

[signed_commits]
ratio_threshold = 0.5
score = 1

[dependency_analysis]
score = 1

[vulnerabilities]
critical_weight = 4
high_weight = 2
medium_weight = 1
low_weight = 0.5
none_weight = 0
max_penalty = 3
score_pass = 1
score_fail = -1
```

---

#### 📍 Examples

```bash
# Basic audit
python githubaudit.py octocat Hello-World

# CI/CD gate: fail if score < 75
python githubaudit.py octocat Hello-World --fail-below 75

# Use a hardened INI config and stricter gate
python githubaudit.py octocat Hello-World --config hardened.ini --fail-below 80

# Skip dependency/vulnerability checks
python githubaudit.py octocat Hello-World --no-deps
```

---

#### 📦 Sample JSON Output

```json
{
  "timestamp": "2025-08-30T12:34:56Z",
  "repository": "octocat/Hello-World",
  "archived": false,
  "disabled": false,
  "last_commit_date": "2025-08-15T09:12:03Z",
  "active_developers_last_90_days": 14,
  "license": "MIT License",
  "security_policy": true,
  "language": "Go",
  "issue_tracking_enabled": true,
  "has_open_or_closed_issues": true,
  "issue_count_open": 120,
  "issue_count_closed": 980,
  "issue_count_total": 1100,
  "abandoned": false,
  "signed_commits": 430,
  "total_commits_sampled": 500,
  "signed_commit_percentage": 86.0,
  "dependency_analysis_enabled": true,
  "dependency_count": 247,
  "dependabot_open_alerts_total": 2,
  "dependabot_open_alerts_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "none": 0
  },
  "trust_score": 83.7,
  "risk_level": "Very Low Risk"
}
```

---

### Permissions Matrix 🔑

Depending on what you want to check, your GitHub token needs different scopes. Here’s a handy guide:

| Feature | Public Repos | Private Repos | Token Scope Required |
|---------|--------------|---------------|----------------------|
| Repo info (license, language, issues, commits) | ✅ | ✅ | `public_repo` (classic) OR fine-grained with **Contents: Read-only**, **Metadata: Read-only** |
| Issues & Search API | ✅ | ✅ | `issues: read` (classic) OR fine-grained with **Issues: Read-only** |
| Security Policy check (`SECURITY.md`) | ✅ | ✅ | Same as contents above |
| Dependency Graph (SBOM) | ✅ | ✅ | Fine-grained: **Dependency graph: Read-only** |
| Dependabot alerts (vulnerabilities) | ✅ | ✅ | **security_events** scope (classic) OR fine-grained with **Dependabot alerts: Read-only** |

> Tip: If you just want to audit **public repos**, a classic PAT with `public_repo` scope is usually enough. For **private repos with vulnerability checks**, add `security_events`.

---

### `dockeraudit.py` – Dockerfile Whisperer 🐳🕵️‍♂️

Ever pulled a Docker image and thought, *“Hmm, hope this wasn’t uploaded by a sleep-deprived intern in 2016”?* Now you don’t have to guess.

#### 🧠 What It Actually Does

- **⭐ Popularity Contest:** Stars = trust points.
- **📅 Update Freshness:** Penalizes stale images.
- **📦 Pull Count Flexing:** More pulls = more trust.
- **🏷️ Tag Count:** Checks number of tags.
- **🏢 Org Activity Check:** Detects active organizations.
- **🙋‍♂️ User Type Scoring:** Org vs individual.
- **✅ Signed or Verified:** Rewards signed/verified images.
- **🎖️ Official Publisher Badge:** Extra points for official badges.

#### 🧾 Output

- **Trust Score** out of 100.
- **Risk Level** (Very Low, Low, Medium, High, Critical).
- Saves results to `docker_audit.json`.

#### 🧪 Usage

```bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--fail-below SCORE]
```

#### 🛠️ Options

| Flag | Description |
|------|-------------|
| `--score-details` | Show detailed scoring breakdown. |
| `--skipssl` | Skip SSL verification. |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value. |

#### 📍 Example

```bash
python dockeraudit.py bitnami/postgresql --score-details --fail-below 80
```

---

### `npmaudit.py` – Because Trusting Random NPM Packages Blindly Is So 2015 📦

#### What It Does

- 📆 Checks last published date.
- 👥 Counts maintainers.
- 📜 Verifies license existence.
- Calculates **Trust Score** and **Risk Level**.

#### 🧪 Usage

```bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below SCORE]
```

#### 🛠️ Options

| Flag | Description |
|------|-------------|
| `--checkdependencies` | Audit dependencies recursively. |
| `--skipssl` | Skip SSL verification. |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value. |

#### 📍 Example

```bash
python npmaudit.py express --checkdependencies --fail-below 60
```

---

### `pypiaudit.py` – Package Whisperer for PyPI 📦🔍

Ever installed a package from PyPI and thought, *“Is this safe, or am I about to adopt someone’s abandoned side project from 2012?”*  
This script asks the hard questions, so you don’t have to.

#### 🧠 What It Actually Does

- **📅 Release Freshness:** Checks when the last version was uploaded.  
- **📈 Release Cadence:** Looks at how many releases in the past year.  
- **📜 License Reality Check:** Detects license presence and whether it’s OSI-approved.  
- **🐍 Python Version Declared:** Verifies `requires_python`.  
- **🏗️ Development Status:** Scores maturity from “Planning” to “Mature.”  
- **📖 Documentation Check:** Measures README length (longer ≠ better prose, but at least *some* effort).  
- **👩‍💻 Maintainer Existence:** Makes sure someone’s name/email is in there.  
- **🛞 Wheel of Fortune:** Checks if wheels are published (with bonus points for manylinux/abi3 and Python 3 tags).  
- **🔗 URL Breadcrumbs:** Homepage, repo, docs links.  
- **🏷️ CI Badge Detector:** Scans README for signs of automated testing.  
- **📦 Dependency Count:** Penalizes heavy dependency chains.  
- **🐛 Vulnerability Lookup:** Cross-checks with OSV advisories.  
- **📊 Trust Score + Risk Level:** Rolls it all up into **health percent** and **risk percent**.  
- **📝 JSON & TL;DR:** Saves results to JSON and prints a human-friendly summary with per-metric comments.  

#### 🧪 Usage

```bash
python pypiaudit.py <package_name> [--pretty] [--timeout 15] [--no-osv] [--fail-above SCORE] [--fail-below SCORE]
```

#### 🛠️ Options

| Flag | Description |
|------|-------------|
| `--pretty` | Pretty-print JSON output. |
| `--timeout` | HTTP timeout in seconds (default: 15). |
| `--no-osv` | Skip OSV vulnerability check. |
| `--fail-above <risk %>` | Exit non-zero if *risk percent* is above this value (preferred). |
| `--fail-below <health %>` | Legacy: exit if *health percent* is below this value. |
| `--out <file>` | Output JSON file path (default: auto-named). |
| `--no-tldr` | Skip TL;DR summary output. |
| `--stdout-json` | Print the JSON payload to stdout. |

#### 📍 Examples

```bash
# Basic audit
python pypiaudit.py requests

# Fail if risk percent > 40
python pypiaudit.py django --fail-above 40

# Pretty JSON + skip OSV check
python pypiaudit.py numpy --pretty --no-osv
```

#### 📦 Sample JSON Output

```json
{
  "package": "requests",
  "collected_at": "2025-09-04T12:34:56Z",
  "score_total_good": 82,
  "score_max": 85,
  "health_percent": 96.5,
  "risk_percent": 3.5,
  "risk_level": "Very Low",
  "risk_level_display": "[VERY LOW]",
  "risk_level_rank": 1,
  "info": {
    "name": "requests",
    "summary": "Python HTTP for Humans.",
    "version": "2.31.0",
    "home_page": "https://requests.readthedocs.io",
    "project_urls": {
      "Source": "https://github.com/psf/requests"
    }
  },
  "highlights": [
    "Active releases in the last 4 months.",
    "Pre-built Python 3 wheels available.",
    "Clear OSI-style license."
  ]
}
```

---

## Quick Start 🏃‍♂️

```bash
git clone  https://github.com/gmartijn/repochecker.git
cd repochecker
pip install -r requirements.txt
```

> Python 3.8+ recommended. You’ll want `requests` installed. `configparser` is standard lib.

---

## CI/CD 💚

Wire `--fail-below` into your pipeline to gate merges:

```bash
python githubaudit.py yourorg yourrepo --fail-below 75
```

- Exit code `0` = pass  
- Exit code `1` = fail threshold or rate limit  
- Exit code `2` = invalid args  

---

## License 📄

See [LICENSE](LICENSE).

## Security Policy 🛡

See [SECURITY.md](SECURITY.md).

## Contributing 🤝

PRs welcome. If you add new criteria, please also:
- Expose it in the INI,
- Document it in this README,
- Keep the scoring denominator fair (max positive points only).

---

Audit like a rockstar. 👨‍🎤

And remember: **Auditors are a lot like Vogons**—they don’t actually *hate* you, they just love bureaucracy so much that they’ll bulldoze your codebase to make way for a hyperspace bypass of compliance checklists. Don’t panic, bring a towel, and maybe a GitHub token. 🪐
