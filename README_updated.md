
# Repository Audit Scripts 🚀

Welcome to the **Repository Audit Scripts** suite – the Swiss Army knife for lazy (read: efficient) developers, DevOps pros, and security sticklers! Why manually check things when a script can do it better, faster, and with fewer coffee stains?

## Why These Scripts? 🤔

You know that one teammate who always asks, "Did you check the license? What about vulnerabilities? Does this Dockerfile follow best practices?" Yeah, this toolkit is how you avoid making eye contact while smugly whispering, “Already done.”

Whether you're trying to impress your boss, outsmart your CI pipeline, or just avoid a Friday fire drill, these scripts have got your back. 🛡️

## Features ✨

### `githubaudit.py` – Your Repo's Personal Inspector 🕵️‍♂️
- **Repository Info:** Gathers all the good stuff: license, primary language, and other cocktail party trivia.
- **Security Policy Check:** Because nothing says “professional” like a documented security policy.
- **Activity Audit:** Checks if the repo is alive, or just a beautiful fossil.
- **License Audit:** Finds out if you’re legally allowed to even look at the code.

### `dockeraudit.py` – Dockerfile Whisperer 🐳
- **Security Checks:** Highlights instructions that might get you featured in a breach postmortem.
- **Output Summary:** Like a report card, but without the crying.

### `npmaudit.py` – Defender of NPM JavaScript Packages 🛡️
- **Dependency Health:** Finds packages older than your high school memories.
- **Audit Score:** Grades your package hygiene with brutal honesty.

## Installation 🛠

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage 🚦

Use these scripts individually, depending on what part of your tech stack you're trying to tame:

### GitHub Repository Audit
```bash
python githubaudit.py --repo <owner/repo>
```

### Dockerfile Audit
```bash
python dockeraudit.py --file path/to/Dockerfile
```

### NPM Package Audit
```bash
python npmaudit.py --path path/to/npm/project
```

## Requirements 📦

Check `requirements.txt` – it's the red carpet for your dependencies.

## License 📄

Yep, we’ve got one. Read the [LICENSE](LICENSE) so the lawyers are happy.

## Security Policy 🛡

Before you find a zero-day, read [SECURITY.md] and learn how to be a responsible adult.

---

Skip the drama. Run the scripts. Audit like a rockstar. 🎸💻
