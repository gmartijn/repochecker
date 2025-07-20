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

- **📟 Repo Resume Review:**  Checks your repo’s name, license, language, and whether you allow issues. Basically a background check for your code.

- **💀 Last Commit Poke Test:**  If your repo hasn’t moved in 90 days, it might be time to send flowers. This script checks if it’s alive or just haunting GitHub.

- **👷‍♂️ Developer Headcount:**  Counts how many people have committed in the last 90 days. More than five? You’ve got a team. Less than five? It’s probably just you and your alt account.

- **⚖️ License Snooping:**  MIT? Apache? GPL? No license at all? You’ll get scored accordingly—and judged silently.

- **🛡️ Security Policy Hunt:**  If `SECURITY.md` isn’t there, we assume your threat model is “fingers crossed.”

- **💻 Language Bias:**  Likes modern languages. If you’re still pushing Perl 5, expect a raised eyebrow.

- **🐛 Bug Count Check:**  If you’ve got issues (and who doesn’t), it’ll find them. Too many, and you’ll get a little slap on the wrist.

- **📈 Trust Score + Risk Level:**  All of the above gets boiled down into a clean score and risk label, perfect for dashboards, reports, or passive-aggressive Slack messages.

- **📦 Output:**  Saves it all to `repo_audit.json`, because screenshots don’t scale.

---

### `dockeraudit.py` – Dockerfile Whisperer 🐳🕵️‍♂️

Ever pulled a Docker image and thought, *“Hmm, hope this wasn’t uploaded by a sleep-deprived intern in 2016”?* Now you don’t have to guess. This script judges your containers faster than your manager judges a 4 p.m. Friday deployment.

#### 🧠 What It Actually Does:

This script inspects Docker Hub metadata like it's evaluating your online dating profile—fast, judgmental, and a little too honest.

- **⭐ Popularity Contest:** Checks how many stars the image has and scores accordingly. No stars? No love 💔.
- **📅 Update Freshness:** Calculates how stale the image is. If it hasn’t been updated in 3 months, it’s probably growing cobwebs 🕸️.
- **📦 Pull Count Flexing:** Measures how many times the image has been pulled. The more, the better. Like social clout, but for containers 💪.
- **🏷️ Tag Count:** More tags might mean great maintenance—or total chaos. Either way, you’re getting judged 🔍.
- **🏢 Org Activity Check:** If the publisher is an active org on Docker Hub, trust goes up. If it's a ghost org, you're on your own 👻.
- **🙋‍♂️ User Type Scoring:** Determines if the uploader is an organization or just some person named “Steve.” Or worse—Steve’s bot.
- **✅ Signed or Verified:** If it’s signed or verified, that’s a huge green flag. We love commitment 💚.
- **🎖️ Official/Verified Publisher Badge:** Got a shiny badge? Instant respect. We're easily impressed.

#### 🧾 Output:

- Calculates a **trust score** out of 100.
- Assigns a **risk level**:
  - `Very Low` 😬
  - `Low` 🧐
  - `Medium` 😐
  - `High` 😎
  - `Critical` 🚨 (Yes, that’s actually a *good* thing here.)

- Results are saved to `docker_audit.json`, perfect for spreadsheets, reports, or Slack-shaming your teammates.

#### 🧪 Usage:

```bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--json]
```

#### 🛠️ Options:

- `--score-details`: Include a breakdown of the score components. For those who want receipts 🧾.
- `--skipssl`: Skips SSL verification. Use only if you trust your sketchy proxy 😅.
- `--json`: Outputs results only to the JSON file. No terminal output, no judgment.

#### 📍 Example:

```bash
python dockeraudit.py bitnami/postgresql --score-details
```

---

### `npmaudit.py` – Defender of JavaScript Dependencies 🛡️

If your `node_modules` folder is older than some interns, you need this.

- **📦 Dependency Archaeology:**  Flags ancient packages you forgot were even installed.

- **🧺 Audit Score:**  Ranks your package hygiene. May sting a little, but it’s for your own good.

- **📊 Trust Score + Risk Level:**  Calculates a trust score and tags the risk from “Very Low” to “Critical,” so you know whether to relax or run screaming.

- **🔍 Dependency Chain Judgment:**  Use `--checkdependencies` to recursively judge every dependency like a code therapist with abandonment issues.

- **📜 Output:**  All judgments are saved to `npm_audit.json`, in JSON format—perfect for spreadsheets, CI pipelines, or Slack-shaming your dev team.

#### 🧪 Usage:

```bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl]
```

#### 🪰 Options:

- `--checkdependencies`:  Enables recursive audits of all direct dependencies. It’s like dragging your whole family to therapy.

- `--skipssl`:  Skips SSL certificate verification. Use only if your network’s weird, your proxy’s weirder, or you're feeling lucky.

#### 🔎 Example:

```bash
python npmaudit.py express --checkdependencies --skipssl
```

#### 🗒 Output Includes:

- Package Name
- Latest Version
- Last Published Date
- Number of Active Maintainers
- License Type
- Trust Score (as a percentage)
- Risk Level ("Very Low" to "Critical")

All of this gets lovingly written to `npm_audit.json`—so you can keep it, grep it, or set it on fire later.

---

## Quick Start 🏃‍♂️

Clone the repo, install dependencies, and start judging your code like it owes you money:

### Quick Start for install
#### Grab the scripts
```bash
git clone https://github.com/yourusername/repo-audit-scripts.git
cd repo-audit-scripts
```

#### Feed the beast
Installation 🛠

Install all the required Python goodies with:

```bash
pip install -r requirements.txt
```

If something breaks, it’s probably because you forgot to activate your virtual environment. Don’t worry—we’ve all done it.

---

### Quick Start for Github Audit

Run your first audit – GitHub repo example:
```bash
python githubaudit.py octocat Hello-World
```

*You're now officially too cool to manually check licenses.*

### Quick Start for NPM Audit

Feeling brave? Audit an NPM package in one line:

```bash
python npmaudit.py express --checkdependencies
```
This will judge `express` and all its dependencies. Side effects may include mild enlightenment or existential dread. Your call.

### Quick Start for Docker Audit

```bash
python dockeraudit.py bitnami/postgresql --score-details
```
This will have a long hard stare at `bitnami\postgresql` and say "Go ahead punk, make my day!" 🤠

---


## License 📄

Yes, there’s a license. No, it doesn’t mean we’re liable for your production mishaps. See [LICENSE](LICENSE) for the thrilling legal prose.

---

## Security Policy 🛡

Before you panic about a zero-day, check our [SECURITY.md](SECURITY.md) for how to be a responsible digital adult.

---

## Contributing 🤝

Spotted a bug? Got a better idea? Feel the urge to automate one more thing so you never have to do it again? PRs welcome!

---

## Final Words 🎸💻

Skip the drama.
Run the scripts.
Audit like a rockstar. 👨‍🎤

```bash
# And remember...
git commit -m "Ran audit scripts. Feeling smug."
```
