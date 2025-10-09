# Conda‑Forge Audit — Calculation Manual (LaTeX Edition) 🤓☕️

You asked for **real math**. You shall receive **real math**. Behold: the scoring model behind `conda_forge_audit.py`, now sprinkled with legit LaTeX blocks so your inner nerd (and your slides) can shine.

---

## TL;DR

We compute five metric scores \(s_m \in [0,100]\), weight them by \(w_m\) with \(\sum w_m = 1\), then clamp to \([0,100]\) and map to a risk bucket.

$$
\mathbf{Overall} \;=\; \sum_{m \in \{\text{vuln},\,\text{fresh},\,\text{pop},\,\text{repo},\,\text{license}\}} 
w_m \cdot s_m,
\qquad \sum_m w_m = 1.
$$

**Default weights:**  
\(w_{\text{vuln}}=0.30,\; w_{\text{fresh}}=0.20,\; w_{\text{pop}}=0.20,\; w_{\text{repo}}=0.20,\; w_{\text{license}}=0.10\).

**Risk levels:**

$$
\text{Risk}=\begin{cases}
\text{Low} & \text{if } \text{Overall}\ge 80,\\[4pt]
\text{Medium} & \text{if } 60 \le \text{Overall} < 80,\\[4pt]
\text{High} & \text{if } 40 \le \text{Overall} < 60,\\[4pt]
\text{Critical} & \text{if } \text{Overall} < 40.
\end{cases}
$$

Weights are user‑tunable via `--weights` and normalized automatically.

---

## Inputs (a.k.a. “Where the facts come from”)

- **Anaconda.org**: latest upload time, latest version, license string, total downloads, versions.
- **GitHub** *(optional but recommended)*: stars, forks, open issues, last push date, archived/disabled flags.
- **OSV.dev** *(on by default)*: vulnerability IDs and severities. We use **severity‑aware** scoring. Disable with `--no-osv` if you enjoy living dangerously.

---

## Metric 1 — Vulnerabilities (OSV, severity‑aware) 🐛

Let \(c\) be the number of OSV vulnerabilities found and \(S=\{s_1,\dots,s_c\}\) the set of per‑vuln numeric severities (CVSS when present). Define

$$
s_{\max} \;=\; \begin{cases}
\max S, & \text{if } c>0 \text{ and numeric severities are present},\\
0, & \text{otherwise}.
\end{cases}
$$

**Base score by worst severity**

$$
\text{base}(c,s_{\max}) \;=\; \begin{cases}
100, & c=0 \text{ or } s_{\max}=0,\\[4pt]
80, & 0 < s_{\max} < 4,\\[4pt]
60, & 4 \le s_{\max} < 7,\\[4pt]
40, & 7 \le s_{\max} < 9,\\[4pt]
20, & s_{\max} \ge 9.
\end{cases}
$$

**Count penalty** (because three medium vulns still ruin your day):

$$
\text{penalty}(c) \;=\; \begin{cases}
0, & c \le 1,\\[4pt]
\min\!\bigl(30,\; 10\cdot\ln(1+c)\bigr), & c>1.
\end{cases}
$$

**Final vulnerability score**

$$
s_{\text{vuln}} \;=\; \max\!\bigl(0,\; \min\!\bigl(100,\; \text{base}(c,s_{\max}) \;-\; \text{penalty}(c)\bigr)\bigr).
$$

**Fallback (no severities available)**

$$
s_{\text{vuln}} \;=\; \begin{cases}
100, & c=0 \text{ or } c \text{ unknown},\\[4pt]
80, & c=1,\\[4pt]
60, & c=2,\\[4pt]
40, & 3 \le c \le 5,\\[4pt]
20, & c>5.
\end{cases}
$$

> Mapping tips: use `--osv-ecosystem` (default `PyPI`) and `--osv-name` if the Conda package name differs from the upstream project. If package lookup fails, we query OSV by GitHub repo URL.

---

## Metric 2 — Freshness (days since latest upload) 🧃

Let \(d\) be the number of days since the latest upload on Anaconda.org. We define

$$
s_{\text{fresh}} \;=\; \begin{cases}
100, & d \le 30,\\[6pt]
20, & d \ge 365,\\[6pt]
100 - (d-30)\cdot\displaystyle\frac{80}{365-30}, & 30 < d < 365,\\[10pt]
50, & \text{if date is unknown (default)}.
\end{cases}
$$

(All scores are clamped to \([20,100]\) in the middle regime.)

---

## Metric 3 — Popularity (total downloads) 📥

Let \(D\) be the total download count across files:

$$
s_{\text{pop}} \;=\; \begin{cases}
10, & D \le 0,\\[4pt]
30, & 0 < D < 10^3,\\[4pt]
50, & 10^3 \le D < 10^4,\\[4pt]
70, & 10^4 \le D < 10^5,\\[4pt]
85, & 10^5 \le D < 10^6,\\[4pt]
95, & D \ge 10^6.\\
\end{cases}
$$

Not perfect science; perfectly explainable in a governance meeting. ✅

---

## Metric 4 — Repo posture (GitHub vibes check) 🧭

Start at \(60\), then adjust:

- **Stars:** \(>500:+15,\; >100:+10,\; >20:+5\)
- **Forks:** \(>50:+10,\; >10:+5\)
- **Open issues:** \(>500:-15,\; >100:-8,\; >20:-3\)
- **Recent push:** \(\le 30\text{ d}:+15,\; \le 180\text{ d}:+8,\; \le 365\text{ d}:+3,\; \text{else}:-10\)
- **Unknown push date:** \(-5\)
- **Archived/disabled:** \(-25\) each

Clamp \(s_{\text{repo}}\) to \([0,100]\). If GitHub is unavailable, we use \(60\) (neutral).

---

## Metric 5 — License (because lawyers) ⚖️

We classify the license string (best‑effort; bring your own edge cases):

$$
s_{\text{license}} \;=\; \begin{cases}
90, & \text{permissive (MIT, BSD, Apache, ISC, zlib, MPL)},\\[4pt]
70, & \text{restrictive (GPL‑3, AGPL, LGPL, EPL, CDLA)},\\[4pt]
40, & \text{proprietary or unknown},\\[4pt]
50, & \text{missing},\\[4pt]
70, & \text{otherwise (generic default)}.\\
\end{cases}
$$

---

## Overall Score & Risk 🎯

Let the metric set be \(M=\{\text{vuln},\text{fresh},\text{pop},\text{repo},\text{license}\}\), with weights \(w_m\) (normalized). Then

$$
\text{Overall} \;=\; \max\!\Bigl(0, \min\!\bigl(100,\; \sum_{m\in M} w_m\, s_m \bigr)\Bigr).
$$

Risk buckets (same as above):

$$
\text{Risk}=\begin{cases}
\text{Low}, & \text{Overall}\ge 80,\\[4pt]
\text{Medium}, & 60 \le \text{Overall} < 80,\\[4pt]
\text{High}, & 40 \le \text{Overall} < 60,\\[4pt]
\text{Critical}, & \text{Overall} < 40.
\end{cases}
$$

Use `--fail-below X` to enforce a gate in CI. The script prints a tidy summary of which packages missed the cutoff before exiting with a non‑zero code. Drama + accountability. 💅

---

## Worked Example (totally realistic, promise)

- OSV: \(c=3\), severities \(\{5.0,\,7.5,\,4.3\}\) \(\Rightarrow s_{\max}=7.5\).
  $$\text{base}=40,\qquad \text{penalty}=\min(30,\,10\ln(1+3)) \approx 13.86,$$
  $$s_{\text{vuln}} \approx 26.1.$$
- Freshness: last upload \(d=90\) days \(\Rightarrow s_{\text{fresh}} \approx 85.7\).
- Popularity: \(D=120{,}000 \Rightarrow s_{\text{pop}}=70\).
- Repo posture: stars 180 \((+10)\), forks 30 \((+5)\), open issues 35 \((-3)\), recent push 20d \((+15)\)  
  \(\Rightarrow s_{\text{repo}} = 60 + 10 + 5 - 3 + 15 = 87\).
- License: Apache‑2.0 \(\Rightarrow s_{\text{license}}=90\).

Overall (default weights):
$$
0.30\cdot 26.1 + 0.20\cdot 85.7 + 0.20\cdot 70 + 0.20\cdot 87 + 0.10\cdot 90
= 65.37 \;\Rightarrow\; \text{Medium}.
$$

---

## Final Notes

This is **decision support**, not divine judgment. It’s explainable, tunable, and grumpy in all the right places. Go forth and audit like the over‑caffeinated hero you are. 🦸‍♂️
