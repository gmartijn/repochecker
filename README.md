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


### 🔍 `npmaudit.py`: Because Trusting Random NPM Packages Blindly Is So 2015

Tired of installing NPM packages that haven’t been touched since Obama was president? Wondering if the three maintainers of your favorite package are actually just one guy named Dave with three email addresses? **Fear not.** `npm_package_audit.py` is here to slap your dependencies with some well-deserved scrutiny.

#### What It Does

This script dives into the NPM registry, pokes around a package’s metadata, and comes back with a *Trust Score™* based on:

- 📆 When it was last published (i.e., is it still alive?)
- 👥 Number of maintainers (more than one sock puppet account, preferably)
- 📜 Whether it has a license (or if you're about to be sued)
- 💡 Bonus points if it ticks multiple boxes

It also calculates a **Risk Level** ranging from "Very Low Risk" (nice!) to "Critical Risk" (run away).

#### Usage

```bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below <score>]
```

#### Options

| Flag | Description |
|------|-------------|
| `--checkdependencies` | Deep audits each dependency, because transitive shame is real. |
| `--skipssl` | Skip SSL verification. Useful for debugging, less so for actual security. |
| `--fail-below <score>` | Exit with a non-zero status if any package scores below your arbitrary threshold of paranoia. |

#### Example

```bash
python npmaudit.py express --checkdependencies --fail-below 60
```

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
