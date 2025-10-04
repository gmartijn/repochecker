*(now with 37% more dad jokes and 0% `rating.UPPER()`)*

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

## Archaeology Corner (Greatest Hits from Earlier)
- v1.1: smarter popularity math, effective-version freshness, repo posture nudge, broader CVSS parsing, PDF/table upgrades.
- v1.0: the brave little script that could (query OSV, pull NuGet bits, score risk, spit PDFs).

