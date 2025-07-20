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

### `dockeraudit.py` – Dockerfile Whisperer 🐳

Ever pulled a Docker image and thought, *â€œHmm, hope this wasnâ€™t uploaded by a sleep-deprived intern in 2016â€?* Now you donâ€™t have to guess.

#### ðŸ§  What It Actually Does:

This script inspects Docker Hub metadata like it's evaluating your online dating profileâ€”fast, judgmental, and a little too honest.

- **â­ Popularity Contest:**  Checks how many stars the image has and scores accordingly. No stars? No love.

- **ðŸ“… Update Freshness:**  Calculates how stale the image is. If it hasnâ€™t been updated in 3 months, itâ€™s probably not bathing either.

- **ðŸ“¦ Pull Count Flexing:**  Measures how many times the image has been pulled. The more, the better. Like social proof, but for containers.

- **ðŸ·ï¸ Tag Count:**  More tags can mean better maintenanceâ€¦ or indecision. Either way, you get points.

- **ðŸ¢ Org Activity Check:**  If the publisher is an active org on Docker Hub, you get bonus trust. Dormant ghost towns lose points.

- **ðŸ™‹ User Type Scoring:**  Determines if the uploader is an individual or an organization. The latter scores higherâ€”sorry, lone wolves.

- **âœ… Signed or Verified:**  If the image is signed or verified, thatâ€™s a green flag.

- **ðŸ”– Official/Verified Publisher Badge:**  If it has a fancy badge, we give it a fancy score bump. Shiny things matter.

#### ðŸ”¢ Output:

- Calculates a **trust score** out of 100 based on all the above
- Labels it with a **risk level**:
  - `Very Low`
  - `Low`
  - `Medium`
  - `High`
  - `Critical` (â† ironically, the best score. Yeah, we may rename this.)

- Dumps the full results into `docker_audit.json`, perfect for grepping, spreadsheets, or blaming in Slack.

#### ðŸ›  Usage:

```bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--json]
```

#### ðŸ§ª Options:

- `--score-details`:  Includes a breakdown of exactly how the score was calculated. Great for bragging or debugging.
- `--skipssl`:  Skips SSL verification (if your network or proxy is... quirky).
- `--json`:  Outputs only to the JSON file, no terminal output.

#### ðŸ“Ž Example:

```bash
python dockeraudit.py bitnami/postgresql --score-details
`


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

Skip the drama.Run the scripts.Audit like a rockstar.

```bash
# And remember...
git commit -m "Ran audit scripts. Feeling smug."
```
