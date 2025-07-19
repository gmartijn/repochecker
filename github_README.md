# 🤖 GitHub Repo Auditor 9000

> “I’m sorry, Dave. I’m afraid this repo is unlicensed.” – HAL 9000 (probably)

Welcome, traveler from the outer reaches of the software galaxy. You've just discovered **GitHub Repo Auditor 9000**, the interstellar tool for evaluating the health and hygiene of GitHub repositories before you let them aboard your metaphorical mothership.

Much like Ripley inspecting the Nostromo’s cargo hold, you’ll want to make sure you’re not bringing aboard anything… buggy. 🚀

---

## 🚀 What is this?

This script probes the structural integrity of a GitHub repository using a variety of suspiciously bureaucratic-sounding metrics:

- ✅ License sanity check (because GPL in the wrong hands is dangerous)
- 🧽‍♂️ Developer activity (are they alive or just ghosts in the commit log?)
- 🔐 Security policy presence (cue dramatic “ACCESS DENIED” door slam)
- 🧠 Language relevance (JavaScript? Good. COBOL? We need to talk.)
- 🐞 Issue tracker insights (how many bugs are *currently breeding*?)
- 📅 Last commit timestamp (Is it active or a relic from the pre-Skynet days?)

All this contributes to a **trust score** from 0 to 100%, like Rotten Tomatoes but for codebases.

---

## 🎯 Why Should I Use This?

You're either:

- A paranoid DevSecOps engineer.
- An open source due diligence specialist with commitment issues.
- An alien lifeform trying to blend into human tech society (in which case: welcome!).

Or you're just tired of cloning repos that haven't seen a commit since *The Matrix Reloaded*.

---

## 🧪 How to Use

Run from the command line with:

```bash
python audit.py <owner> <repo> [--skipssl] [--output results.json]
```

### Example:

```bash
python audit.py netflix polly --output doomed.json
```

---

## 🛠 Features

- Smart API use with built-in rate limit warning – no need to guess when GitHub will slam the brakes like HAL in safe mode.
- Pretty JSON output suitable for feeding into your compliance droids.
- SSL optional for those who live dangerously (*looking at you, Mad Max*).
- Handles missing data gracefully – because not every repo is a shining starship.

---

## 💀 Scoring Logic

Like all powerful artifacts, this one uses ancient knowledge:

| Condition                            | Points |
| ------------------------------------ | ------ |
| Last commit within 90 days           | +1     |
| 5+ developers active in last 90 days | +1     |
| MIT/Apache license                   | +1     |
| GPL license                          | +0.5   |
| MPL/LGPL/Other or None               | 0/-1   |
| SECURITY.md found                    | +1     |
| Popular language (Python/JS/etc)     | +1     |
| Issues enabled                       | +1     |
| Too many issues (>10)                | -1     |

Final score is converted to a risk level:

- **80-100%**: Very Low Risk (🛡️ Ironclad like the USS Enterprise)
- **60-79%**: Low Risk (🚀 Safe for now\...)
- **40-59%**: Medium Risk (🤔 Proceed with caution)
- **20-39%**: High Risk (🚨 Red alert!)
- **0-19%**: Critical Risk (💥 Like hiring Bender as a sysadmin)

---

## 📦 Output

A JSON file with all the juicy audit details. Share it with your team. Print it. Frame it. Offer it to the compliance gods.

---

## 🧙‍♂️ Fun Facts

- This script respects rate limits better than Han Solo respects speed limits.
- Still no support for auditing Death Star blueprints, sorry.
- Will not argue with your licensing decisions (but will silently judge them).

---

## 💫 Coming Soon?

- Organization-wide audits (like the Starfleet’s annual code review).
- CSV/HTML reporting.
- Snarkier risk messages (optional: `--enable-sass`).

---

## 🧼 Disclaimer

> This tool does not currently factor in the **reputation of the vendor or maintainer**. In other words, even if the repo was last touched by the ghost of Linus Torvalds himself, you're still on your own. Choose wisely.

---

## 🧠 Final Thought

> “The repo is out there, Neo. It’s looking for you. And it will find you… if you want it to.” – Morpheus

Happy auditing, cybernauts! 📂🚀

---

