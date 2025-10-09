# Conda‑Forge Audit — Calculation Manual (Ridiculously Honest Edition) 🤓☕️

So you want to know how the sausage is made. Excellent. Pull up a chair, top up the espresso, and behold the *glorious math* behind `conda_forge_audit.py`—now with OSV severity‑aware spice and a sensible risk-o‑meter.

---

## TL;DR (for the caffeinated in a hurry)
We compute five sub‑scores on a 0–100 scale, weight them, sum them, clamp to 0–100, and map to a risk level.

\[
\textbf{Overall} = \sum_{m \in \{\text{vuln},\ \text{fresh},\ \text{pop},\ \text{repo},\ \text{license}\}} w_m \cdot s_m
\quad\text{with}\quad \sum w_m = 1
\]

**Defaults:**  
- Vulnerabilities `w_vuln = 0.30`  
- Freshness `w_fresh = 0.20`  
- Popularity `w_pop = 0.20`  
- Repo posture `w_repo = 0.20`  
- License `w_license = 0.10`

**Risk levels:**  
- `Score ≥ 80` → **Low** 🟢  
- `60 ≤ Score < 80` → **Medium** 🟡  
- `40 ≤ Score < 60` → **High** 🟠  
- `Score < 40` → **Critical** 🔴

You can override weights with `--weights freshness=0.4,popularity=0.2,repo_posture=0.2,license=0.2` (they’re auto‑normalized).

---

## Inputs & Data Sources (aka “Where we rummage for facts”)
- **Anaconda.org (channel: `conda-forge` by default):** latest version, latest upload time, license, total downloads, versions.  
- **GitHub (optional but recommended):** stars, forks, open issues, last push, archived/disabled flags.  
- **OSV.dev (on by default):** vulnerabilities by *package + ecosystem* (default: PyPI) or by *repo URL* as a fallback. We parse severities and compute a severity‑aware score. You can turn it off with `--no-osv` (you rebel).

Pro‑tip: `--skipssl` (or `NO_SSL_VERIFY=1`) disables TLS verification if your CI lives in a “fun” network. Use with caution and a side‑eye from your security team. 😬

---

## Metric 1 — Vulnerabilities (OSV, severity‑aware) 🐛
We ask OSV for vulns. If it returns nothing or has no severity data, we fall back to a count‑only model. Otherwise we use the **worst CVSS** we see and apply a small **count penalty**.

### Severity‑aware scoring
Let `count = #vulns` and `max_cvss = max(severities)`, where severities are CVSS base scores if available.

Base score:
- `count == 0` **or** `max_cvss == 0` → **100**
- `max_cvss ≥ 9.0` → **20**
- `7.0 ≤ max_cvss < 9.0` → **40**
- `4.0 ≤ max_cvss < 7.0` → **60**
- `0.1 ≤ max_cvss < 4.0` → **80**

Penalty for “many friends”:
\[
\text{penalty} = \begin{cases}
0 & \text{if } \text{count} \le 1 \\
\min(30,\ \ln(1+\text{count}) \times 10) & \text{otherwise}
\end{cases}
\]

Final vulnerability score:
\[
s_{\text{vuln}} = \max\big(0, \min(100,\ \text{base} - \text{penalty})\big)
\]

### Count‑only fallback (no severities)
- `0` → **100**  
- `1` → **80**  
- `2` → **60**  
- `3–5` → **40**  
- `>5` → **20**  
- `None/unknown` → **100** (optimistic default; feel free to grumble)

### Notes & edge cases
- If you want to map to a different ecosystem, use `--osv-ecosystem` (e.g., `npm`, `crates.io`, etc.).  
- Force the OSV package name with `--osv-name` if the Conda name differs from the underlying project.  
- If package lookup fails, we try repo‑based lookup via GitHub URL.

---

## Metric 2 — Freshness (days since latest upload) 🧃
Let `d = days since last upload` (from Anaconda.org).  
- If `d ≤ 30` → **100**  
- If `d ≥ 365` → **20**  
- Else → **linear** between `100` (at 30 days) and `20` (at 365 days):

\[
s_{\text{fresh}} = 100 - (d-30)\cdot \frac{80}{365-30}\quad\text{clamped to }[20,100]
\]

If no date is available or parsing fails → **50** (“Schrödinger’s maintenance”).

---

## Metric 3 — Popularity (total downloads) 📥
From Anaconda.org (sum across files):
- `≤ 0` → **10**  
- `< 1,000` → **30**  
- `< 10,000` → **50**  
- `< 100,000` → **70**  
- `< 1,000,000` → **85**  
- `≥ 1,000,000` → **95**

Is it perfect? No. Is it easy to explain in a security committee without a 40‑slide appendix? Absolutely.

---

## Metric 4 — Repo posture (GitHub vibes check) 🧭
Start at **60** and nudge:
- **Stars:** `>500` +15, `>100` +10, `>20` +5  
- **Forks:** `>50` +10, `>10` +5  
- **Open issues:** `>500` −15, `>100` −8, `>20` −3  
- **Recent push:** `≤30d` +15, `≤180d` +8, `≤365d` +3, else −10; unknown −5  
- **Archived/disabled:** −25 each (🧊)

Clamp to `[0,100]`. If GitHub data is missing, we default to **60** (“neutral shrug”).

---

## Metric 5 — License (because lawyers bill by the hour) ⚖️
We squint at the license string:
- Permissive (MIT/BSD/Apache/ISC/zlib/MPL) → **90**  
- Restrictive (GPL‑3/AGPL/LGPL/EPL/CDLA) → **70**  
- Proprietary/unknown → **40**  
- Missing → **50**  
- Otherwise → **70**

Yes, it’s coarse. No, your Legal team will not sign off on emojis in the scorecard (we tried).

---

## Overall Score & Risk 🎯
Weights default to: `0.30/0.20/0.20/0.20/0.10` for (vuln/fresh/pop/repo/license). We normalize custom weights, then:

\[
\text{Overall} = \text{clamp}_{[0,100]}\!\Big( \sum w_i \cdot s_i \Big)
\]

Risk buckets:
- **Low** `≥ 80`
- **Medium** `60–79.9`
- **High** `40–59.9`
- **Critical** `< 40`

Use `--fail-below X` to make CI throw a dramatic tantrum. It now prints *which* packages failed and by *how much*—you’re welcome. 💅

---

## Worked Example (totally real, not made up 🙃)
- Vulnerabilities: OSV finds `count=3`, severities `[5.0, 7.5, 4.3]` → `max_cvss=7.5` → base `40`, penalty `ln(1+3)*10 ≈ 13.86` → `s_vuln ≈ 26.1`
- Freshness: last upload 90 days ago → linear ≈ `100 - (60 * 80/335) ≈ 85.7`
- Popularity: 120,000 downloads → **70**
- Repo posture: stars 180 (+10), forks 30 (+5), open issues 35 (−3), recent push 20d (+15) → `60 + 10 + 5 − 3 + 15 = 87`
- License: Apache‑2.0 → **90**

Overall (defaults):
\[
0.30\cdot 26.1 + 0.20\cdot 85.7 + 0.20\cdot 70 + 0.20\cdot 87 + 0.10\cdot 90
= 7.83 + 17.14 + 14 + 17.4 + 9
= 65.37 \Rightarrow \textbf{Medium}
\]

And yes, that single HIGH severity dragged the party down like a lead balloon.

---

## CLI Flags That Influence Scoring
- `--weights …` — tweak metric importance (auto‑normalized).  
- `--no-osv` — disable OSV lookups (vuln score becomes optimistic or count‑only fallback).  
- `--osv-ecosystem` / `--osv-name` — control how OSV is queried.  
- `--skipssl` (or `NO_SSL_VERIFY=1`) — turn off TLS verification (don’t make this a lifestyle).  
- `--explain` — print a step‑by‑step breakdown so auditors can nod sagely.

---

## CSV Columns (so spreadsheets can judge you)
- `name, channel, latest_version, license, latest_upload, total_downloads`  
- `gh_repo, gh_stars, gh_forks, gh_open_issues, gh_pushed_at`  
- `osv_count, osv_max_cvss`  
- `score_vulnerabilities, score_freshness, score_popularity, score_repo_posture, score_license`  
- `overall, risk`

Pin it to a PowerPoint and watch stakeholders pretend to read it while they look for the risk color. (It’s **Medium**. It’s always Medium.)

---

## Philosophy & Trade‑offs
This is a **decision‑support** score, not a divine truth. It’s explainable, tunable, and relatively robust against hype and neglect. It will not replace human judgment, but it will absolutely replace tedious meeting questions with smug one‑liners. 😇

Now go forth and audit like the over‑caffeinated hero you were born to be.
