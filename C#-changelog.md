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