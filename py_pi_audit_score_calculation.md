# 🚀 PyPI Audit Score Guide 🧑‍💻

> Written by an auditor with an unhealthy love for JSON and mathematics. If you’ve ever seen someone excited about both spreadsheets *and* curly braces, that’s who wrote this. 📊➕📦

## TL;DR (Quick & Dirty Summary)
This tool audits your package metadata with the enthusiasm of an accountant at tax season. It adds points for good behavior, subtracts them by omission, then flips the math at the end so low numbers = good and high numbers = scary. 🧮

- **Lower risk percent = safer ✅**
- **Higher risk percent = sketchier ☠️**

Your **risk percent** maps neatly to a **risk level** (see table below). No actuarial degree required (but auditors still drool over this stuff). 🤓

---

## The Calculation 🧮

Mathematically speaking, the process looks like this:

\[
health\_percent = \frac{\text{sum of all good scores}}{\text{sum of all weights}} \times 100
\]

\[
risk\_percent = 100 - health\_percent
\]

If math makes you sweat, just remember: 
- A high health score = “this project is alive and well” 💪
- A high risk score = “this project is coughing ominously” 😷

It’s not rocket science. Well, unless you’re literally using it in a rocket. 🚀

---

## Risk Levels 🎯

| Risk Percent ≤ | Risk Level |
|---:|:---|
| **15** | **Very Low 🟢** |
| **30** | **Low 🟢** |
| **50** | **Medium 🟡** |
| **70** | **High 🟠** |
| **100** | **Critical 🔴** |

Use `--fail-above N` to fail builds if any package’s risk percent goes above that.  
Legacy: `--fail-below N` still checks `health_percent < N`. (Think of it as the old “fitness test” system.)

---

## What Gets Measured 📏
Here’s the full list of metrics, their weights, and what they actually mean. 

| Metric | Weight | How it earns points | Example |
|---|---:|---|---|
| Recent Release | 15 | Full points if released today; decays over a year. | Updated last week = 👍; last touched in 2015 = 👴 |
| Release Cadence | 10 | 6+ releases in a year = full points. | A package sneezing patches monthly = ✅ |
| License Present | 10 | Full points if license exists. | MIT → ✅, “License: none” → 🚨 |
| OSI License | 5 | Full if OSI-style license. | Apache-2.0 = ✅ |
| Requires-Python | 8 | Full if declared. | `>=3.9` → ✅ |
| Dev Status | 8 | Stable = full points; Inactive = meh. | "Production/Stable" → 🏆 |
| README | 5 | Needs to be more than a haiku. | "# MyLib" won’t cut it. |
| Maintainer Present | 5 | Someone listed. | At least one name/email. |
| Wheels | 8 | Latest ships wheels. | Saves your laptop fan from meltdown. |
| Manylinux/abi3 | 4 | Wheel works widely. | More penguins can run it. 🐧 |
| Py3 Wheel | 4 | Explicit support for Python 3. | Because Python 2 is a fossil. 🦖 |
| Project URLs | 5 | Repo/docs/homepage present. | GitHub link = ✅ |
| CI Badge Hint | 2 | README shows CI badge. | "build passing" spotted. |
| Dependency Count | 5 | 0–25 deps = full, >50 = chaos. | 150 deps? Really? |
| OSV Vulns | 6 | Zero vulns = full points. | A clean bill of health. |

---

## Example Walkthrough 🧾
Say we check `hypothetical-awesome-lib`:
- Released 30 days ago → **14/15**
- 3 releases this year → **5/10**
- MIT License → **10/10 + 5/5**
- `requires_python = ">=3.10"` → **8/8**
- Stable status → **8/8**
- README is a novel → **5/5**
- Maintainer: yes → **5/5**
- Wheels: yes, manylinux, py3 → **8/8 + 4/4 + 4/4**
- URLs present → **5/5**
- CI badge present → **2/2**
- Dependencies: 12 → **5/5**
- OSV vulns: 0 → **6/6**

**health_percent** = ~95% → **risk_percent** ≈ 5% → **Risk: Very Low 🟢**

---

## FAQ (Frequently Argued Questions) ❓
**Q. Why do you care how long the README is?**  
A. Because a README shorter than your grocery list won’t help anyone. 🛒

**Q. Why not use stars or download counts?**  
A. Stars are free. Metadata isn’t. ⭐

**Q. My library has no dependencies — isn’t that great?**  
A. Yes. But balance matters. Otherwise single-file joke projects would be “Very Low Risk.” 😂

**Q. Can I tweak the weights?**  
A. Of course. But remember: if you inflate one metric too much, you’ll be explaining to senior management why their favourite dashboard suddenly shows big red scores. And they *hate* red. 🔴📈

---

## Operational Bits 🛠️
- **Quality gate:** `--fail-above N` → exit **2** if any package exceeds this risk percent.  
- **Legacy gate:** `--fail-below N` → exit **2** if any package’s health percent < N.  
- **Operational issues:** network/PyPI hiccups → exit **1**.  
- **Success:** everything peachy → exit **0**. 🎉

The script emits a JSON report by default and prints a TL;DR with per-metric comments. Perfect for CI logs, PR reviews, or winning arguments with your team’s resident auditor. 👔

---

## Final Advice 🧳
- Keep dependencies healthy. 🍎  
- Pin `requires_python`. 🐍  
- Red scores make management nervous. Keep them green unless you enjoy urgent calendar invites. 📅

