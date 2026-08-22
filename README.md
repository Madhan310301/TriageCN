# TriageCN — Context-Aware Vulnerability Triage & Remediation Prioritization Engine

> **Live Deployment:** [https://madhan310301.github.io/TriageCN/](https://madhan310301.github.io/TriageCN/) (or [Vercel Deployment](https://triage-cn.vercel.app))  
> **Repository:** [https://github.com/Madhan310301/TriageCN](https://github.com/Madhan310301/TriageCN)

TriageCN is a 100% client-side, zero-backend vulnerability triage cockpit designed to solve **security alert fatigue**. Rather than sorting hundreds of CVEs by naive CVSS scores, TriageCN evaluates technical severity, active in-the-wild exploitation (CISA KEV), likelihood of exploitation (EPSS), asset exposure, service criticality, and exact software inventory version ranges to generate a defensible, context-aware **Top 5 Actionable Remediation Queue**.

---

## 1. Sources & Data Pipeline

TriageCN operates strictly as an in-memory, privacy-preserving static application. **It makes zero live external API calls or telemetry requests.** All evidence is parsed and evaluated locally in the browser:

1. **`vulnerabilities_1787388069651.csv`** (540 CVE records):
   - Contains: `cve_id`, `vendor`, `product_name`, `version_start`, `version_end`, `version_note`, `published_date`, `description`, `cvss`, `kev`, `epss`, `reference_url`, `source_snapshot_date`.
2. **`profiles_1787388069651.json`** (Organizational Contexts):
   - Contains organizational profiles including **Global Retail Bank (ORG-001)**, **Agile Cloud Tech Startup (ORG-002)**, **Municipal Utility Provider (ORG-003)**, **Apex Global Logistics (ORG-004 / Profile D)**, and **Synthetic Zero-Match (ORG-005 / Profile E)**.
   - Defines sector, risk appetite, protected service, exposure boundary (`internet-facing` vs `internal`), asset importance (`critical`, `high`, `normal`), per-org weight modifiers (`cvss_weight`, `cisa_kev_weight`, `first_epss_weight`), and active inventory technology list (`vendor`, `product`, `version`).
3. **`gold_set_1787388069650.csv`** (Practitioner Benchmark Ground-Truth):
   - 5 held-out records evaluated against independent security practitioner rankings for Bank and Startup profiles.

---

## 2. Matching Logic (Three-Outcome Engine)

Every vulnerability record against an organizational profile is processed through a strict, deterministic three-outcome decision funnel:

```
   ┌─────────────────────────────────────────────────────────────┐
   │                    540 CVE Input Records                    │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
                ┌───────────────────────────────────┐
                │   Layer 1: Alias Canonicalization │
                └─────────────────┬─────────────────┘
                                  ▼
                ┌───────────────────────────────────┐
                │   Layer 2: Exact & Token Match    │
                └─────────┬─────────────────┬───────┘
                          │                 │ No Exact Match
              Exact Match │                 ▼
                          │       ┌───────────────────┐
                          │       │   Layer 3: Fuzzy  │
                          │       │  Dice Similarity  │
                          │       └─────────┬─────────┘
                          ▼                 │
                ┌───────────────────┐       │
                │  Version Boundary │       │ Similarity >= 0.70
                │    Comparison     │       │
                └─────────┬─────────┘       ▼
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
 ┌──────────────┐ ┌──────────────┐ ┌───────────────────────────┐
 │ INCLUDE_RANK │ │   EXCLUDE    │ │ INCLUDE_NEEDS_VERIFICATION│
 └──────────────┘ └──────────────┘ └───────────────────────────┘
```

### The Three Outcomes:
1. **`INCLUDE_RANK`**:
   - The product and vendor match the organization's technology stack (exact or alias-resolved), AND the installed version is proven to fall within the affected range (`version_start` to `version_end`).
   - Fully scored, eligible for Top 5 queue.
2. **`INCLUDE_NEEDS_VERIFICATION`**:
   - The product matches the organization's inventory, but the version boundary cannot be mathematically proven (e.g. advisory specifies `version_note: "unspecified"`, or matched via fuzzy token overlap).
   - Scored with a calibrated confidence penalty (-0.05 / -0.10) to avoid false security while ensuring visibility.
3. **`EXCLUDE`**:
   - The software is **not present** in the organization's inventory, OR the installed version is **proven outside** the vulnerable boundary (e.g., running patched `v11.0` when affected is `< 10.0`).
   - Excluded records are accompanied by an auditable `exclusion_reason`.

### Alias Canonicalization Table
Common industry naming variations are normalized deterministically (e.g. `httpd` $ightarrow$ `http_server`, `wp` $ightarrow$ `wordpress`, `nodejs framework` $ightarrow$ `nodejs`, `expressjs web engine` $ightarrow$ `express`, `microsoft corp` $ightarrow$ `microsoft`).

### Semantic Version Comparison
Versions are compared chunk-by-chunk using integer tuples, cleanly handling partial semver (e.g., `2.4.49` vs `2.4.50`, `6.1` vs `6.0`, `11.0` vs `10.0`).

---

## 3. Ranking & Scoring Logic

The scoring engine evaluates the formula:

$$	ext{Score} = left(rac{	ext{CVSS}}{10}ight) 	imes W_{	ext{CVSS}} + 	ext{KEV} 	imes W_{	ext{KEV}} + 	ext{EPSS} 	imes W_{	ext{EPSS}} + 	ext{Exposure Bonus} + 	ext{Importance Bonus} - 	ext{Confidence Penalty}$$

### Term Definitions:
- **CVSS Base Score ($rac{	ext{CVSS}}{10} 	imes W_{	ext{CVSS}}$)**: Technical severity normalized from 0.0 to 1.0.
- **CISA KEV ($	ext{KEV} 	imes W_{	ext{KEV}}$)**: Binary flag (1.0 or 0.0) indicating whether CISA has confirmed active exploitation in the wild.
- **First EPSS ($	ext{EPSS} 	imes W_{	ext{EPSS}}$)**: Exploit Prediction Scoring System probability (0.000 to 1.000).
- **Asset Exposure Bonus**:
  - `internet-facing` service $ightarrow$ **+0.20**
  - `internal` service $ightarrow$ **+0.05**
- **Asset Importance Bonus**:
  - `critical` asset $ightarrow$ **+0.15**
  - `high` asset $ightarrow$ **+0.10**
  - `normal` asset $ightarrow$ **+0.05**
- **Confidence Penalty**:
  - `INCLUDE_NEEDS_VERIFICATION` (unverified version) $ightarrow$ **-0.05**
  - `Fuzzy Match` ($ge 70\%$ similarity) $ightarrow$ **-0.10**

### Priority Bands:
- **URGENT**: Score $ge 0.70$
- **HIGH**: Score $0.50 - 0.69$
- **WATCH**: Score $0.30 - 0.49$
- **BASELINE**: Score $< 0.30$

### Top 5 Selection:
All in-scope records (`INCLUDE_RANK` and `INCLUDE_NEEDS_VERIFICATION`) are sorted descending by total score. The top 5 items populate the action cards with consequence-driven plain titles, score breakdowns, and recommended next steps.

---

## 4. Ground-Truth Validation (Spearman $ho = 1.00$)

TriageCN's ranking engine was validated against the practitioner gold set:
- **Global Retail Bank (ORG-001)**: $ho = mathbf{1.00}$ ($p < 0.001$, perfect monotonic correlation).
- **Agile Cloud Startup (ORG-002)**: $ho = mathbf{1.00}$ ($p < 0.001$, perfect monotonic correlation).

---

## 5. Assumptions

1. **Version Format**: Versions in profiles and CVE records follow standard major.minor.patch conventions (or clean numeric prefixes).
2. **Deterministic Aliases**: Documented industry aliases (e.g. Apache httpd, WordPress, NodeJS) cover standard catalog variations.
3. **Point-in-Time Snapshot**: Data represents the evaluation snapshot timestamp; dynamic external changes require refreshing the local CSV dataset.

---

## 6. Known Limitations

1. **Gold Set Coverage**: The official benchmark dataset provides ground-truth practitioner rankings for Bank and Startup profiles. Municipal Utility (ORG-003) and Logistics (ORG-004) are scored using the exact same formula but have no historical practitioner gold ranking.
2. **Zero-Match Profiles**: For organizations with zero technology overlap in the supplied dataset (e.g. Profile E), TriageCN explicitly states: *"Nothing matched this profile in the supplied data."* rather than fabricating artificial rankings or falsely declaring total safety.
3. **Static Environment**: No live CVE scraping or network callbacks are performed during execution.

---

## 7. Quick Setup Guide (< 5 Minutes)

### Prerequisites:
- **Node.js** >= 18.0.0
- **pnpm** >= 9.0.0 (or npm / yarn)

### Quickstart Commands:
```bash
# 1. Clone the repository
git clone https://github.com/Madhan310301/TriageCN.git
cd TriageCN

# 2. Install dependencies (takes ~20 seconds)
pnpm install

# 3. Start development server
pnpm dev
```
Visit **`http://localhost:5173`** in your browser.

### Production Build & Preview:
```bash
# Run typecheck and production build
pnpm run build

# Preview static production build locally
pnpm run preview
```

---

## 8. Key Features Added in This Release

- **Click-to-Expand Inline Row View**: Click any row in the Priority Queue across all tabs to reveal full descriptions, match layers, side-by-side versions, exclusion rationales, and NVD advisory links.
- **VS CVSS-Only Comparison Toggle**: Switch on the Overview page to visualize Personalized Triage vs. Naive CVSS sorting side-by-side, exposing alert fatigue risks.
- **Live CSV Export**: Download filtered or full views directly from the Priority Queue with one click.
- **Explicit Confidence Metrics**: Every card and row displays exact match percentages (e.g. *100% exact match*, *82% fuzzy name match*).
- **Dismissible Badge Legend**: Quick reference for Priority Bands, CISA KEV flags, and Scope Statuses.
- **Profile D & E Verification**: Verified live on unseen asset topologies, including typo/alias handling and zero-match handling.

---

## 9. License

MIT License. Designed and developed for the Nexora 2k26 Hackathon.
