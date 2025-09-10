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

---

### ☕ Caffeine Consumption Disclaimer

Running these scripts at 2 AM after your **fifth espresso** may result in:

- Unnecessarily strict thresholds (everything looks risky at 200 bpm).
- Overly creative commit messages.
- Philosophical debates with your cat about OSI licenses.

Use responsibly. Scripts don’t cause insomnia—**auditors do.**

---

### `dockeraudit.py` – Dockerfile Whisperer 🐳🕵️‍♂️

Ever pulled a Docker image and thought, *“Hmm, hope this wasn’t uploaded by a sleep-deprived intern in 2016”?* Now you don’t have to guess.

#### 🧠 What It Actually Does

- ⭐ Popularity Contest: Stars = trust points.
- 📅 Update Freshness: Penalizes stale images.
- 📦 Pull Count Flexing: More pulls = more trust.
- 🏷️ Tag Count: Checks number of tags.
- 🏢 Org Activity Check: Detects active organizations.
- 🙋‍♂️ User Type Scoring: Org vs individual.
- ✅ Signed or Verified: Rewards signed/verified images.
- 🎖️ Official Publisher Badge: Extra points for official badges.

#### 🧪 Usage

```bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--fail-below SCORE]
```

---

### `npmaudit.py` – Because Trusting Random NPM Packages Blindly Is So 2015 📦

#### 🧠 What It Does

- 📆 Checks last published date.
- 👥 Counts maintainers.
- 📜 Verifies license existence.
- Calculates **Trust Score** and **Risk Level**.

#### 🧪 Usage

```bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below SCORE]
```

---

### `pypi_audit.py` – Package Whisperer for PyPI 📦🔍

Ever installed a package from PyPI and thought, *“Is this safe, or am I about to adopt someone’s abandoned side project from 2012?”*  
This script asks the hard questions, so you don’t have to.

#### 🧠 What It Actually Does

- 📅 Release Freshness + Cadence.
- 📜 License Reality Check (presence + OSI-approved).
- 🐍 Requires-Python check.
- 🏗️ Development Status (from Planning to Mature).
- 📖 README / docs check.
- 👩‍💻 Maintainer presence.
- 🛞 Wheels (with manylinux/abi3 and Python 3 bonus).
- 🔗 URLs: homepage, repo, docs.
- 🏷️ CI Badge detection.
- 📦 Dependency count + penalty for heavy packages.
- 🐛 OSV vulnerability check.
- 📊 Trust Score + Risk Level.
- 📝 JSON & TL;DR output.
- **NEW:** `--skipssl` flag for SSL verification skipping.

#### 🧪 Usage

```bash
python pypi_audit.py <package_name> [--file packages.txt] [--pretty] [--timeout 15] [--no-osv] [--fail-above SCORE] [--fail-below SCORE] [--out report.json] [--no-tldr] [--stdout-json] [--skipssl]
```

---

### `pypi_audit_report.py` – Reporting Sidekick 📊

After you’ve run multiple audits, merge the JSON outputs and feed them here.

#### 💼 What It Does

- Reads merged JSON (lists, JSON Lines, concatenated objects, etc.).
- Exports to **CSV** or **Excel**.
- Columns: `package, score_total_good, health_percent, risk_level, recent_release, dependency_count, indicators`.
- Indicators = joined “highlights” from the audit JSON.
- Excel adds frozen header, filters, and **Risk Level coloring**:
  - Critical → Red
  - High → Orange
  - Medium → Yellow
  - Low → Green
  - Very Low → Blue

#### 🧪 Usage

```bash
python pypi_audit_report.py merged.json -o report.csv --xlsx report.xlsx
```

---

## Quick Start 🏃‍♂️

```bash
git clone https://github.com/gmartijn/repochecker.git
cd repochecker
pip install -r requirements.txt
```

---

## CI/CD 💚

Wire `--fail-below` or `--fail-above` into your pipeline to gate merges:

```bash
python githubaudit.py yourorg yourrepo --fail-below 75
python pypi_audit.py requests --fail-above 40
```

---

## License 📄

See [LICENSE](LICENSE).

## Security Policy 🛡

See [SECURITY.md](SECURITY.md).

## Contributing 🤝

PRs welcome. If you add new criteria, also:
- Document it in this README,
- Keep the scoring denominator fair.

---

☕ Fun fact: These scripts were clearly written by an **over-caffeinated information security officer** who thought “relaxing spare time project” meant parsing JSON until 3 AM. If you feel personally attacked, don’t worry—you’re among friends here.

---

Audit like a rockstar. 👨‍🎤
