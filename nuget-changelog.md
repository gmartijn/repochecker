# NuGet Audit — The Extremely Serious Changelog (with jokes) 🤡📦

*(Now fortified with extra sarcasm, fewer facepalms, and a clinically responsible amount of CVSS.)*

## v1.3 — 2025-10-04

### ✨ New Features (oooh, shiny)
- **Historical gossip mode:** `--historical` shows the *all‑time* count of OSV advisories for a package, plus how many don’t affect the audited version. Think “celebrity scandals,” but for DLLs.
- **Weighted nostalgia:** `--history-weight FLOAT` lets you factor those past vulns into the overall score as a sixth dimension. We auto‑normalize weights so math keeps its dignity.
- **CI mood switch:** `--fail-below FLOAT` exits with **code 3** if the overall score is under your line in the sand. Perfect for pipelines that like tough love.
- **CVSS glow‑up:** Recognizes `CVSS_V3`, `CVSS_V3.1`, **and** `CVSS_V4` where provided. Future‑proof(ish).

### 🧠 Scoring Bits You’ll Quote In Meetings
- **Five core dimensions:** Vulnerabilities, Freshness, Popularity, Repo Posture, License. Each 0–100, all clamped, nicely behaved.
- **Optional sixth:** History (0–100 based on past vuln count; default weight 0.0). If you include it, we shuffle the weights so the pie still equals 1.0. 🥧
- **Repo realism:** No repo? Small penalty. Archived/disabled? Big side‑eye. Stale pushes? Lose a few points. Your repo should text back occasionally.

### 🧰 CLI Toppings
- `package` & `lockfile` subcommands remain delicious.
- `--osv-only` for fast triage, still incompatible with `--fail-below` (no score to judge = no judgment).
- `--no-github` when you’re rate‑limited or in a bunker.
- `--skipssl` for corporate proxies that play TLS dress‑up (use responsibly).

### 🐛 Buglets Tucked In
- Help text de‑gremlined; examples updated for the new flags.
- PDF tables get another nudge to auto‑fit columns without interpretive wrapping.

### 🧪 Handy Spells
```bash
# Add historical vibes to the score with a lil' weight
python nuget-audit.py package --name Serilog --json --historical --history-weight 0.25

# CI: fail if overall < 75
python nuget-audit.py package --name Newtonsoft.Json --json --fail-below 75

# Lockfile triage; fail if anything < 70
python nuget-audit.py lockfile --path ./packages.lock.json --json --fail-below 70
```

---

*(now with 37% more dad jokes and 0% `rating.UPPER()`)*


## v1.2 — 2025-10-04

### ✨ New Features (fresh out of the oven)
- **`--skipssl` (global):** For those times your corporate proxy insists on “helping.”
  - Disables TLS certificate verification (`SESSION.verify = False`).
  - Politely hushes `InsecureRequestWarning` (if `urllib3` is around).
  - Big disclaimer energy: use only when you trust the proxy and your life choices.

### 🧰 CLI UX & Helpfulness
- **Full parameter cheat sheet on exit code 2:** Run the script without a subcommand and it prints the parser help *and* a human-friendly quick reference. Your future self will thank Present You.
- **Examples updated:** Help text now showcases `--skipssl` like a proud parent at a school play.

### 🛡️ Reliability & Cleanliness
- **Safer stderr output:** Replaced fragile `sys.stderr.write("...")` snippets with `print(..., file=sys.stderr)` to avoid EOL gremlins.
- **Backoff still chill:** HTTP helpers retain exponential backoff and `Retry-After` respect for `429/503`. (APIs gonna API.)

### 🐛 Bug Fixes (we fed them to /dev/null)
- **Argparse shenanigans:** Removed a stray line that previously produced `ValueError: unknown action "False"`.
- **All-caps drama resolved:** `rating.UPPER()` is now the perfectly ordinary and emotionally stable `rating.upper()`.
- **Indentation yoga:** Fixed inconsistent indentation around `main()` so Python stops side-eyeing us.
- **String literal tantrums:** Eliminated raw multiline strings that caused `SyntaxError: EOL while scanning string literal`.

### 📦 What Stayed Solid (from earlier upgrades)
- **NuGet hydration:** Registration pages get fully hydrated; we don’t stop at stubs.
- **Repo URL spelunking:** Prefer repository metadata from registration; normalize GitHub URLs.
- **Effective-version freshness:** Publish date is taken from the version you’re actually auditing.
- **Popularity sanity:** Log scale that maps `1e3 → 0` and `1e7 → 100`, clamped nicely.
- **PDF polish:** Legible x‑axis labels, tidy tables, rating badge that behaves.

---

## TL;DR for Humans in a Hurry
- New global flag: `--skipssl` (use sparingly).
- Running with no subcommand now prints a **super-help** page (and exits 2).
- Various gremlins stomped. Confidence increased by 17%.*

\* Percentage may be made up but emotionally accurate.

---

## Handy Invocations
```bash
# List auditable packages from a lockfile, skipping SSL verification
python nuget_security_audit_enhanced.py --list --path ./packages.lock.json --skipssl

# Single package audit: JSON only
python nuget_security_audit_enhanced.py package --name Serilog --json

# Single package -> PDF report
python nuget_security_audit_enhanced.py package --name Serilog --pdf serilog_audit.pdf

# Lockfile sweep, OSV-only (fast triage)
python nuget_security_audit_enhanced.py lockfile --path ./packages.lock.json --osv-only
```

---


## v1.1 — 2025-10-03

### ✨ New Features (sparkly and nutritious)
- **Hydrated NuGet pages**: We now follow registration `@id` links like a golden retriever chasing a frisbee. Stub pages? Consider them un-stubbed.
- **Repo URL treasure hunt**: Digs through registration metadata to find the *real* repo. If it’s on GitHub, we sanitize the URL like a proper neat freak.
- **Freshness for your *actual* version**: Scoring now uses the publish date of the version you’re auditing, not always the latest. No more anti-aging cream for old packages.
- **CLI power-ups**:
  - `--no-github`: Skip GH calls. Great for air-gapped fortresses or when GitHub says “rate limited, bestie.”
  - `--osv-only`: Just the vulns, ma’am. Faster than a caffeine-fueled CI run.

### 🧠 Behavior Tweaks (smarter, sassier)
- **Popularity math that doesn’t lie**: `1e3 → 0` and `1e7 → 100`. Finally, the vibes match the math.
- **Repo posture reality check**: No repo URL? Tiny penalty. (Open source or it didn’t happen.)
- **License vibes**: Gentle side-eye for `LGPL`/`MPL`, bigger side-eye for `NOASSERTION`/`CUSTOM`. GPL still gets the “are you sure about prod?” eyebrow.

### 🛡️ Robustness (because APIs be like that)
- **Backoff & Retry-After**: Plays nice with `429/503`. Exponential backoff with just enough patience to feel mature.
- **Registration helpers**: `_iter_reg_items`, `_published_of_version`, semver sorting—like WD-40 for metadata.

### 📊 Reporting (prettier PDFs, fewer tears)
- **Summary page**: Shows the effective version’s publish date and a rating badge that actually uses `rating.upper()`. (Yes, we fixed that.)
- **Charts**: X-axis labels rotated with care. Your neck—and your printer margins—will thank us.
- **Vuln tables**: Tries to auto-fit columns so CVEs don’t cosplay as wrap art.
- **Lockfile PDF**: Columns adapt for `--osv-only`, because minimalism is a feature.

### 🧾 JSON (for friendly robots)
- Includes **both** `requested_version` and `version` (effective). Minimal brain gymnastics required.

### 🧰 CLI UX (less guessy, more classy)
- No subcommand? We show help and exit with code `2`. (The “go read the manual” of exit codes.)
- `--list` still lists like a pro, with optional `--path`.

### 🐛 Bug Fixes (we squashed them humanely)
- **Argparse oopsie**: Removed the wild `action="true" in ()` line that shouted *ValueError!* in Python.
- **UPPER drama**: `rating.UPPER()` is now the perfectly ordinary `rating.upper()`. We promise we’re okay.

---
# CHANGELOG.md
*(a dramatic retelling of bugs vanquished and flags bestowed)*

## Archaeology Corner (Greatest Hits from Earlier)
- v1.1: smarter popularity math, effective-version freshness, repo posture nudge, broader CVSS parsing, PDF/table upgrades.
- v1.0: the brave little script that could (query OSV, pull NuGet bits, score risk, spit PDFs).
