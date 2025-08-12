# Repository Audit Scripts 🚀

Welcome to **Repository Audit Scripts** – the Swiss Army knife for lazy (read: efficient) developers, DevOps gremlins, and security-conscious caffeine addicts. Why manually check things when a script can do it faster, better, and without having to read another 400-page compliance doc?

---

## Why These Scripts? 🤔

You know that one teammate who always pipes up in the meeting with, “Did anyone check the license? Are there vulnerabilities? Does this Dockerfile follow best practices?”

This toolkit is how you avoid eye contact and smugly mutter, “Already done.”

Whether you're trying to impress your boss, appease your CI pipeline, or just want to avoid triggering a Friday fire drill, these scripts are your trusty sidekicks. 🧘‍♂️

---

## Features ✨

### `githubaudit.py` – The Repo Investigator You Didn’t Know You Needed 🕵️‍♀️🍸

This script snoops through your GitHub repo like a nosy neighbor with an API key. Think of it as your overly judgmental auditor with strong opinions and a thing for JSON.

#### 💼 What It Actually Does:

- **📟 Repo Resume Review:**  Checks your repo’s name, license, language, and whether you allow issues.
- **💀 Last Commit Poke Test:**  Detects inactivity or abandonment.
- **👷‍♂️ Developer Headcount:**  Counts committers in the last 90 days.
- **⚖️ License Snooping:**  Scores based on license type.
- **🛡️ Security Policy Hunt:**  Looks for `SECURITY.md`.
- **💻 Language Bias:**  Gives points for popular, modern languages.
- **🐛 Bug Count Check:**  Compares open/closed issues for resolution ratio.
- **✍️ Signed Commit Detection:**  Checks for cryptographically signed commits.
- **📈 Trust Score + Risk Level:**  Turns all of this into a neat number and risk label.
- **📦 Output:**  Saves everything to `repo_audit.json`.

#### 🧪 Usage:

```bash
python githubaudit.py <owner> <repo> [--skipssl] [--output <file>] [--max-commits N] [--fail-below SCORE]
```

#### 🛠️ Options:

| Flag | Description |
|------|-------------|
| `--skipssl` | Skip SSL certificate verification. |
| `--output` | Output file for audit results (default: `repo_audit.json`). |
| `--max-commits` | Number of commits to check for signed commits (default: 500). |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value (0–100). Perfect for CI/CD gates. |

#### 📍 Examples:

```bash
python githubaudit.py octocat Hello-World
python githubaudit.py octocat Hello-World --fail-below 75
```

---

### `dockeraudit.py` – Dockerfile Whisperer 🐳🕵️‍♂️

Ever pulled a Docker image and thought, *“Hmm, hope this wasn’t uploaded by a sleep-deprived intern in 2016”?* Now you don’t have to guess.

#### 🧠 What It Actually Does:

- **⭐ Popularity Contest:** Stars = trust points.
- **📅 Update Freshness:** Penalizes stale images.
- **📦 Pull Count Flexing:** More pulls = more trust.
- **🏷️ Tag Count:** Checks number of tags.
- **🏢 Org Activity Check:** Detects active organizations.
- **🙋‍♂️ User Type Scoring:** Org vs individual.
- **✅ Signed or Verified:** Rewards signed/verified images.
- **🎖️ Official Publisher Badge:** Extra points for official badges.

#### 🧾 Output:

- **Trust Score** out of 100.
- **Risk Level** (Very Low, Low, Medium, High, Critical).
- Saves results to `docker_audit.json`.

#### 🧪 Usage:

```bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--fail-below SCORE]
```

#### 🛠️ Options:

| Flag | Description |
|------|-------------|
| `--score-details` | Show detailed scoring breakdown. |
| `--skipssl` | Skip SSL verification. |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value. |

#### 📍 Example:

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

#### 🧪 Usage:

```bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below SCORE]
```

#### 🛠️ Options:

| Flag | Description |
|------|-------------|
| `--checkdependencies` | Audit dependencies recursively. |
| `--skipssl` | Skip SSL verification. |
| `--fail-below <score>` | Exit with non-zero status if trust score is below this value. |

#### 📍 Example:

```bash
python npmaudit.py express --checkdependencies --fail-below 60
```

---

## Quick Start 🏃‍♂️

```bash
git clone https://github.com/yourusername/repo-audit-scripts.git
cd repo-audit-scripts
pip install -r requirements.txt
```

---

## License 📄

See [LICENSE](LICENSE).

## Security Policy 🛡

See [SECURITY.md](SECURITY.md).

## Contributing 🤝

PRs welcome.

---

Audit like a rockstar. 👨‍🎤
