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
- **👷‍♂️ Developer Headcount:** Counts unique committers in the last 90 days.
- **⚖️ License Snooping:** Scores based on license family.
- **🛡️ Security Policy Hunt:** Looks for `SECURITY.md`.
- **💻 Language Bias:** Gives points for popular, modern languages.
- **🐛 Bug Count Check:** Compares open/closed issues for a resolution ratio.
- **✍️ Signed Commit Detection:** Samples commits and checks for GPG-verified signatures.
- **📈 Trust Score + Risk Level:** Rolls everything into a neat number and risk label.
- **📝 Configurable Scoring (NEW):** All thresholds, weights, popular language list, and license scoring are configurable via **INI**.
- **🧪 CI-friendly:** `--fail-below` exits non-zero if the score doesn’t meet your bar.
- **📦 Output:** Saves everything to `repo_audit.json`.
- **🔑 Prefers a GitHub token:** Yes, it *works* without one, but the unauthenticated rate limit is basically training wheels. Enjoy 403s, or set a token like a responsible adult. 😇

#### 🧪 Usage

```bash
python githubaudit.py <owner> <repo>   [--skipssl]   [--output <file>]   [--max-commits N]   [--fail-below SCORE]   [--config path/to/config.ini]   [--write-default-config path/to/new.ini]
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

#### ⚙️ Configuration (INI)

`githubaudit.py` can load all scoring parameters from an INI file. You can generate a starter file like this:

```bash
python githubaudit.py --write-default-config github_audit.defaults.ini
```

Then tweak to taste and run:

```bash
python githubaudit.py octocat Hello-World --config github_audit.defaults.ini
```

**What’s configurable?**

- **Recent commit:** `good_days`, `abandoned_days`, `score`
- **Active developers:** `threshold`, `score` (still counts unique authors over the last **90 days**)
- **License scoring:** per-family scores for `mit`, `apache`, `gpl`, `mpl`, `lgpl`, and a default `other`
- **Security policy:** `score`
- **Language:** `popular` (comma-separated list), `score`
- **Issue tracking:** `score`
- **Issue resolution:** `min_issues`, `ratio_threshold`, `score_pass`, `score_fail`
- **Signed commits:** `ratio_threshold`, `score` (only counted if commits were sampled)

**Example `config.ini`**

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
```

> ℹ️ **Scoring math:** The final score is normalized to 0–100 by dividing by the sum of the **max positive points available** for criteria that apply (e.g., signed-commit points only count in the denominator if commits were sampled).

#### 🔥 Strongly recommended: set a GitHub token (unless you enjoy 403s)

Running unauthenticated means you’ll kiss the tiny rate limit wall early and often. Save yourself the sadness:

**macOS/Linux (bash/zsh):**
```bash
export GITHUB_TOKEN=ghp_yourtokenhere
```

**Windows (PowerShell):**
```powershell
setx GITHUB_TOKEN "ghp_yourtokenhere"
```

Use a classic or fine-grained personal access token with read access (for public repos, default scopes are typically fine). Then restart your shell. Your future self says thanks.

#### 🔐 Example permissions for your GitHub token

If you like granting “*all the things*,” maybe don’t. Here’s the **minimal** stuff the script needs.

**Fine-grained PAT (recommended):**
- **Repository access:** *Only selected repositories* (or *All public repositories* if you’re scanning public stuff)
- **Repository permissions:**
  - **Contents: Read-only** ✅ *(required: repo details, commits list, `SECURITY.md` content)*
  - **Issues: Read-only** ✅ *(required if you audit **private** repos; the Search API respects repo permissions)*
  - **Metadata: Read-only** ✅ *(implicit / auto-granted)*
- Everything else: **No access** 🚫

**Classic PAT (legacy):**
- **Public repos only:** Use **`public_repo`** (good enough to bump rate limits).
- **Need private repos too?** You’ll need **`repo`** (yes, it’s broad; that’s why fine‑grained tokens exist).
- You do **not** need `admin:repo_hook`, `workflow`, `write:packages`, or any other spicy scopes—unless you enjoy compliance audits and heartburn.

#### 📍 Examples

```bash
python githubaudit.py octocat Hello-World
python githubaudit.py octocat Hello-World --fail-below 75
python githubaudit.py octocat Hello-World --config hardened.ini --fail-below 80
```

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

## Quick Start 🏃‍♂️

```bash
git clone https://github.com/yourusername/repo-audit-scripts.git
cd repo-audit-scripts
pip install -r requirements.txt
```

> Python 3.8+ recommended. You’ll want `requests` installed. `configparser` is part of the Python standard library.

---

## CI/CD 💚

Wire `--fail-below` into your pipeline to gate merges:

```bash
python githubaudit.py yourorg yourrepo --fail-below 75
```

Return code `1` = block the build; return code `0` = let it through.

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
