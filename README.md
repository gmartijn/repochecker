# Repository Audit Scripts 🚀

Welcome to **Repository Audit Scripts** -- the Swiss Army knife for lazy
(read: efficient) developers, DevOps gremlins, and security‑conscious
caffeine addicts. Why manually check things when a script can do it
faster, better, and without reading another 400‑page compliance doc?

------------------------------------------------------------------------

## Why These Scripts? 🤔

You know that one teammate who always pipes up in the meeting with, "Did
anyone check the license? Are there vulnerabilities? Does this
Dockerfile follow best practices?"

This toolkit is how you avoid eye contact and smugly mutter, "Already
done."

Whether you're trying to impress your boss, appease your CI pipeline, or
just want to avoid triggering a Friday fire drill, these scripts are
your trusty sidekicks. 🧘‍♂️

------------------------------------------------------------------------

## Feature Line‑Up ✨

### `githubaudit.py` -- The Repo Investigator You Didn't Know You Needed 🕵️‍♀️🍸

This script snoops through your GitHub repo like a nosy neighbor with an
API key. Think of it as your overly judgmental auditor with strong
opinions and a thing for JSON.

**What It Does** - 📟 Repo Resume Review: basic metadata & settings. -
💀 Last Commit Poke: inactivity/abandonment detection. - 👷‍♂️ Active Devs:
unique committers in last 90 days (bots ignored). - ⚖️ License Scoring:
permissive ≈ happier auditors. - 🛡️ SECURITY.md seeker. - 💻 Language
bias: points for popular modern stacks. - 🐛 Bug pressure: issue
open/closed ratio. - ✍️ Signed commits: sample GPG verification. - 📦
Dependency graph detection. - 🕳️ Dependabot alerts (severity aware). -
📈 Trust Score + Risk Level. - 📝 INI‑configurable scoring. - 🧪
CI‑friendly: `--fail-below` gates merges. - 📤 Output:
`repo_audit.json`. - 🔑 Tip: Use a token unless you enjoy 403s.

**Usage**

``` bash
python githubaudit.py <owner> <repo> \
  [--skipssl] [--output <file>] [--max-commits N] \
  [--fail-below SCORE] [--config path/to/config.ini] \
  [--write-default-config path/to/new.ini] [--no-deps] [--sbom]
```
### NEW SBOM MODE!! What this does:

add `--sbom` to the command line.

The repo audit will: - Combine repository posture with dependency risk -
Include supply-chain exposure into trust scoring - Provide stronger
audit evidence for DORA/NIS2 discussions.

It will generate an Software Packet Data Exchange (SPDX) file formatted file 
owner_project_sbom.spdx.json (e.g. gmartijn_repochecker_sbom.spdx.json), which 
can be parsed using the dependency tool in this repository (sbom_supply_chain_risk.py).

------------------------------------------------------------------------

### `dockeraudit.py` -- Dockerfile Whisperer 🐳🕵️‍♂️

Ever pulled a Docker image and thought, *"Hmm, hope this wasn't uploaded
by a sleep‑deprived intern in 2016"*? Now you don't have to guess.

**What It Does** - ⭐ Popularity: stars → trust. - 📅 Freshness: stale
images lose points. - 📦 Pull counts: flex responsibly. - 🏷️ Tag
coverage. - 🏢 Org activity. - 🙋 User type: org vs. individual. - ✅
Signed/verified + official badges.

**Usage**

``` bash
python dockeraudit.py <image_name> [--score-details] [--skipssl] [--fail-below SCORE]
```

------------------------------------------------------------------------

### `npmaudit.py` -- Because Trusting Random NPM Packages Blindly Is So 2015 📦

**What It Does** - 📆 Last publish date. - 👥 Maintainer count. - 📜
License presence. - 🎯 Trust Score + Risk Level.

**Usage**

``` bash
python npmaudit.py <package_name> [--checkdependencies] [--skipssl] [--fail-below SCORE]
```

------------------------------------------------------------------------

### `pypi_audit.py` -- Package Whisperer for PyPI 📦🔍

Ever installed a PyPI package and thought, *"Is this safe, or am I
adopting someone's abandoned side project from 2012?"*\
This script asks the hard questions so you don't have to.

**What It Does** - 📅 Release freshness + cadence. - 📜 License reality
check (presence + OSI‑approved). - 🐍 Requires‑Python sanity. - 🏗️ Dev
status classifier. - 📖 README/docs presence. - 👩‍💻 Maintainer
presence. - 🛞 Wheel niceness (manylinux/abi3, Py3 bonus). - 🔗 URLs:
homepage/repo/docs. - 🏷️ CI badge detection. - 📦 Dependency counts. -
🐛 OSV vulnerability check. - 📊 Trust Score + Risk Level. - 📝 JSON &
TL;DR output. - 🧪 CI‑friendly: `--fail-below`, `--fail-above`. - ⚙️
`--skipssl` for quirky proxies.

**Usage**

``` bash
python pypi_audit.py <package_name> [--file packages.txt] [--pretty] [--timeout 15] \
  [--no-osv] [--fail-above SCORE] [--fail-below SCORE] [--out report.json] \
  [--no-tldr] [--stdout-json] [--skipssl]
```

------------------------------------------------------------------------

### `pypi_audit_report.py` -- Reporting Sidekick 📊

Merge multiple audits and export to CSV/Excel with nice risk colors
(because slides).

**Usage**

``` bash
python pypi_audit_report.py merged.json -o report.csv --xlsx report.xlsx
```

------------------------------------------------------------------------

### `nuget-audit.py` -- NuGet/.NET Package Clairvoyant 🔮📦

**What It Does** - OSV.dev for NuGet ecosystem (version‑aware). - NuGet
metadata spelunking (downloads, dates, license). - Optional GitHub
posture. - Weighted score across
Vulns/Freshness/Popularity/Repo/License. - Pretty PDF export with charts
(because meetings). - `--skipssl` for proxied CI.

**Usage**

``` bash
python nuget-audit.py package --name Newtonsoft.Json --version 13.0.3 --pdf newtonsoft_audit.pdf
```

------------------------------------------------------------------------

### NEW: `conda_forge_audit.py` -- Conda‑Forge Package Auditor 🧪🐍

Finally: a Conda‑Forge auditor with **OSV severity‑aware** vulnerability
scoring and GitHub repo enrichment.

**What It Does** - 🧬 **Anaconda.org** metadata: latest version, latest
upload, license, total downloads, versions. - 🐛 **OSV.dev lookups**:
package‑first (default ecosystem: **PyPI**), fallback to **repo URL**.
Severity‑aware scoring (max CVSS + small count penalty).\
See the **[Conda‑Forge Calculation
Manual](conda_forge_audit_calculation.md)** for all the tasty math. - 🐙
**GitHub posture (optional)**: stars, forks, open issues, recent push,
archived/disabled. - 🧮 **Weighted overall score** across
Vulnerabilities / Freshness / Popularity / Repo Posture / License. - 🧪
**CI‑friendly**: `--fail-below` prints a clear summary *and* exits
non‑zero. - 🧾 **CSV/JSON** outputs + **bulk mode** (file with names). -
🧰 **Tunable weights** via `--weights freshness=0.4,...`
(auto‑normalized). - 🌐 **Proxy fun**: `--skipssl` (or
`NO_SSL_VERIFY=1`). Use sparingly; auditors are watching. 👀

**Usage**

``` bash
# Single package
./conda_forge_audit.py --name numpy

# JSON output
./conda_forge_audit.py -n pandas --json

# Bulk (one name per line), with CSV
./conda_forge_audit.py --input packages.txt --csv conda_audit.csv

# Gate CI
./conda_forge_audit.py -n scikit-learn --fail-below 70

# Explain scoring steps
./conda_forge_audit.py -n xarray --explain

# OSV ecosystem/name mapping
./conda_forge_audit.py -n fastapi --osv-ecosystem PyPI --osv-name fastapi

# In… spicy CI networks
./conda_forge_audit.py -n numpy --skipssl
```

**Flags You'll Actually Use** - `--json` · `--csv PATH` · `--input PATH`
· `--explain` - `--weights KEY=VAL,...` (normalized) -
`--fail-below N` - `--no-osv` · `--osv-ecosystem NAME` ·
`--osv-name NAME` - `--skipssl` (or `NO_SSL_VERIFY=1`)

**Files** - Script: [`conda_forge_audit.py`](conda_forge_audit.py)\
- Math (funny version):
[`conda_forge_audit_calculation.md`](conda_forge_audit_calculation.md)

------------------------------------------------------------------------

------------------------------------------------------------------------

## NEW: SBOM Supply Chain Risk Analyzer 🧬🔥

### `sbom_supply_chain_risk.py`

Modern incidents are rarely caused by *your* code.\
They are caused by the 900 dependencies your code politely invited into
production.

This script ingests an **SPDX SBOM** and calculates a **supply-chain
risk score** using OSV.dev (independent vulnerability intelligence ---
no Dependabot dependency required).

### What It Does

-   Parses SPDX relationships to determine real dependencies
-   Queries OSV.dev for vulnerabilities
-   Evaluates version pinning quality
-   Penalizes floating branches (`main`, `master`, vibes)
-   Flags weak SBOM evidence (`NOASSERTION`, `filesAnalyzed=false`)
-   Produces JSON & Markdown reports
-   Generates auditor-explainable risk scoring

### Usage

``` bash
python sbom_supply_chain_risk.py sbom.json --format markdown --out report.md
```

### Score Interpretation

  Score    Meaning
  -------- -------------------------
  0-29     Controlled
  30-54    Needs adult supervision
  55-74    Incident pending
  75-100   Call legal

### Why this matters

You can now say:

> "We perform continuous supply-chain monitoring based on SBOM
> analysis."

instead of:

> "pip install but responsibly."

------------------------------------------------------------------------


## Quick Start 🏃‍♂️

``` bash
git clone https://github.com/gmartijn/repochecker.git
cd repochecker
pip install -r requirements.txt
```

------------------------------------------------------------------------

## CI/CD 💚

Wire `--fail-below` (or `--fail-above` where supported) into your
pipeline to gate merges:

``` bash
python githubaudit.py yourorg yourrepo --fail-below 75
python pypi_audit.py requests --fail-above 40
./conda_forge_audit.py -n numpy --fail-below 70
```

------------------------------------------------------------------------

## License 📄

See [LICENSE](LICENSE).

## Security Policy 🛡

See [SECURITY.md](SECURITY.md).

## Contributing 🤝

PRs welcome. If you add new criteria, also: - Document it in this
README, - Keep the scoring denominator fair, - Add a unit test or six
(you animal).

------------------------------------------------------------------------

☕ Fun fact: These scripts were clearly written by an **over‑caffeinated
information security officer** who thought "relaxing spare time project"
meant parsing JSON until 3 AM. If you feel personally attacked, don't
worry---you're among friends here.

Audit like a rockstar. 👨‍🎤
