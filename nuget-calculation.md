# NuGet Security Audit — How The Score Is Cooked (Chef’s Kiss™)

*Because nothing says “enterprise risk management” like five numbers, a bar chart, and a mild sense of superiority.*

This document explains how the **NuGet/C# package security audit** script (the one in your canvas right now) turns raw metadata into a single, glorious score and a tidy PDF.

---

## Ingredients (Data Sources)

1. **OSV.dev** — We ask `/v1/query` for the package in the **NuGet** ecosystem.\
   - If a version is provided (the **effective** version; see below), OSV returns **only** the vulns that affect that exact version.\
   - We summarize each vuln with:\
     - `_max_cvss` — the maximum CVSS we can find (CVSSv3/3.1/4 supported; we’ll rummage in database fields if needed).
     - `_sev_label` — human-readable severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`).

2. **NuGet APIs**\
   - **Search API** gives us: latest version, `totalDownloads`, `licenseExpression`, `projectUrl`.\
   - **Registration API** (hydrated if necessary) gives us per-version metadata, especially **publish timestamps**.\
   - We also spelunk for **repository URLs**, because transparency is romantic.

3. **GitHub API (optional)** — Only used if a GitHub repo is detected **and** you didn’t pass `--no-github`.\
   We grab: `stargazers_count`, `open_issues_count`, `pushed_at`, `archived`/`disabled`, and `license.spdx_id`.

4. **Networking niceness**\
   - Light retry/backoff. We respect `Retry-After` on `429/503` like civilized citizens.\
   - Behind a fussy proxy? `--skipssl` flips `SESSION.verify = False` and hushes the warning (use only if your proxy is your BFF).

---

## Which Version Are We Judging? (The “Effective Version”)

- If you pass `--version`, that’s the one on trial.\
- Otherwise we use **latest** from NuGet.\
- For **freshness**, we prefer the **publish date** of the effective version. If we can’t find it, we fall back to the most recent publish date we can see.

---

## Five Secret Herbs & Spices (Subscores 0–100)

Every subscore starts at **100** and loses points for risk signals. Everything is clamped to the polite range of **0…100**.

### 1) Vulnerabilities (OSV, per *effective* version)
Penalties for both **how many** and **how spicy**:
```
vul_score = 100
- 15 points per vulnerability (capped at 70 total)
- extra penalty by MAX CVSS across vuln list:
    >= 9.0  → -20
    >= 7.0  → -12
    >= 4.0  →  -6
clamp to 0..100
```
If you have zero vulns: congrats—your score starts at 100, continue to ruin it elsewhere.

### 2) Freshness (days since publish)
```
fresh = 100
if no publish date     → -15
elif days <= 30        →  -0
elif days <= 90        → -10
elif days <= 180       → -20
elif days <= 365       → -35
else                   → -55
clamp to 0..100
```
Translation: freshly baked packages are tasty; ancient bread is croutons.

### 3) Popularity (total downloads, log scale)
We map the download count using a **log₁₀** scale so “popular” means… actually popular.
```
lg  = max(0, log10(downloads))
pop = ((lg - 3) / (7 - 3)) * 100
clamp to 0..100
```
Mnemonic: `1e3 → 0`, `1e7 → 100`. Everything else lands gracefully in between.

### 4) Repo Posture (GitHub vibes)
Start at 100; apply “vibes tax” as needed:
```
repo = 100
if no repo URL              → -15
if archived or disabled     → -40
if stars < 10               → -10
elif stars < 100            →  -5
if no pushed_at             → -10
else:
  if days since push > 365  → -25
  elif > 180                → -15
  elif > 90                 →  -8
clamp to 0..100
```
If nobody’s touched the repo since your last haircut, we have questions.

### 5) License (NuGet or GitHub SPDX)
```
license = 100
if no license               → -20
elif contains "GPL"/"AGPL"  → -10    (enterprisey side-eye)
elif contains "LGPL"/"MPL"  →  -5    (milder eyebrows)
if NOASSERTION/CUSTOM       → -15
clamp to 0..100
```
We don’t judge your life choices—just your license choices.

---

## The Final Sauce (Weights & Rating)

We blend the five subscores using fixed weights:
```
weights = {
  vulnerabilities: 0.40,
  freshness:       0.20,
  popularity:      0.15,
  repo_posture:    0.15,
  license:         0.10,
}
overall = round(sum(subscore[k] * weight[k]), 1)
```
Then we name it:
```
overall >= 80  → low
>= 60          → medium
>= 40          → high
else           → critical
```
If you get “critical” and your heart rate rises: good, that’s the correct response.

---

## Missing Stuff? (We Thought Of That)
- No publish date? **Freshness** takes a modest hit (`-15`).\
- No repo URL? **Repo posture** loses a few points (`-15`).\
- No stars/push info? Also a mild penalty—talk to your repo about communication.\
- No license? **License** score takes a `-20` nap.\
Everything is clamped to **0..100**; nobody gets negative swag.

---

## Outputs You Can Brag About

### JSON (package mode)
- Top-level: `package`, `requested_version`, `version` (effective), `overall`, `rating`\
- `nuget`: `latest_version`, `published`, `total_downloads`, `license_expression`, `project_url`, `repo_url`\
- `github`: `stars`, `open_issues`, `pushed_at`, `archived`, `disabled`, `license`\
- `vulnerabilities`: per-issue `{id, max_cvss, severity}`\
- `scores`: the five subscores

### PDF
1. **Summary** page (metadata, counts, overall & rating badge)  
2. **Bar chart** of those five subscores (labels rotated just enough to be legible)  
3. **Vulnerability table** (up to 20 entries, trimmed descriptions, polite layout)

---

## Flags That Change Your Vibe
- `--osv-only`: just pull OSV vulns and print JSON. No scoring, no charts, no small talk.
- `--no-github`: skip GH repo calls (posture might sag—absence makes the score grow colder).
- `--skipssl`: disables TLS verification (behind a trusted proxy only; otherwise, yikes).

---

## Care & Feeding (Tips)
- Pin a specific `--version` for reproducible OSV results.\
- If CI has no internet fancy business, run with `--no-github`.\
- Want a PDF? `pip install matplotlib` or the plot fairy won’t visit.

---

## Hilarious FAQ (Frequently Asked Quibbles)

**Q: Why do I see a vulnerability on the OSV website, but the script returns none?**\
A: OSV’s page can show “there exists a vuln for this package (ever).” Our script asks, “does it affect *this* version?” If you’re using a fixed version where the issue is already patched, the script calmly says “nope.” Version matters—like milk expiry dates.

**Q: My package is ancient but very loved. Why is freshness so judgy?**\
A: We’re not saying “old = bad.” We’re saying “old and unmaintained = eyebrow.” If it’s truly stable and dependency-free, feel free to take the freshness penalty as a badge of stoic maturity.

**Q: We don’t have a GitHub repo. Are we doomed?**\
A: No, but we remove some posture points because we can’t see activity signals. If your code lives elsewhere and thrives, you’re fine—just know we can’t validate your glow-up.

**Q: GPL in license made our score sad. Why?**\
A: Many enterprises treat strong copyleft as “handle with care.” The score reflects typical enterprise caution, not a legal verdict. (Also: not legal advice. We are but humble number chefs.)

**Q: Should I enable `--skipssl`?**\
A: Only when your proxy politely breaks TLS and you consent to this chaotic energy. Disable it when you’re back on normal internet like a respectable adult.

**Q: What does a ‘low’ rating actually mean?**\
A: It means the indicators look healthy *right now*. Not a guarantee, not a certification, just a good vibe check. Keep monitoring—software entropy is undefeated.

**Q: Can you also show “historical” vulns?**\
A: In this script version we stick to per-version vulns (that’s what matters for *your* build). If you want the “all-time drama” meter added, say the word and we’ll wire it up.

---

Go forth. Audit boldly. And may your bars be tall and your PDFs un-clipped.
