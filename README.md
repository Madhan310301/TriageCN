# TriageCN — Context-Aware Vulnerability Triage & Remediation Prioritization Engine

> **Repository:** [https://github.com/Madhan310301/TriageCN](https://github.com/Madhan310301/TriageCN)

TriageCN is a 100% client-side, zero-backend vulnerability triage cockpit designed to eliminate **security alert fatigue**. Rather than sorting hundreds of CVEs by naive CVSS scores, TriageCN evaluates technical severity, active in-the-wild exploitation (CISA KEV), likelihood of exploitation (EPSS), asset exposure, service criticality, and exact software inventory version ranges to generate a defensible, context-aware **Top 5 Actionable Remediation Queue**.

---

## 1. Zero Live Network Dependency & Data Pipeline

TriageCN is engineered to run **100% offline and locally** with zero external network or live API dependencies in the judged path, strictly adhering to the hackathon brief (*"The demo must run without paid data, paid software, or a live API dependency"*):

- **Zero Runtime Network Calls**: No `fetch()`, `axios`, WebSockets, or live vulnerability data API queries (no live calls to NIST NVD, CISA KEV, or FIRST EPSS).
- **Zero Live LLM Dependency**: Title generation, score explanations, and next-step actions are 100% deterministic template-driven using only data present in the local CVE row.
- **Static In-Memory Bundling**: All 540 CVE records and organizational profiles are loaded into browser memory at build/startup time.
- **Traceability Reference Links**: The `reference_url` fields in the UI are static HTML anchor hyperlinks to NIST NVD for human practitioner provenance inspection on manual click — they are never queried programmatically at runtime.

### Data Sources & Field Schemas:
1. **`vulnerabilities.csv`** (540 CVE records):
   - `cve_id`: Unique Common Vulnerabilities and Exposures identifier (e.g. `CVE-2026-1769`).
   - `vendor`: Software vendor name (e.g. `SecNet`, `Apache`, `NodeJS`).
   - `product_name`: Affected software package or product (e.g. `Web Application Firewall`, `http_server`).
   - `version_start`: Lower boundary of affected version range.
   - `version_end`: Upper boundary of affected version range.
   - `version_note`: Advisory notes or exceptions from vendor guidance.
   - `published_date`: Disclosure/publishing date.
   - `description`: Plaintext summary of the vulnerability mechanism and impact.
   - `cvss_base_score`: Base technical severity score (0.0 to 10.0).
   - `cisa_kev`: Boolean indicator of active in-the-wild exploitation (`TRUE` / `FALSE`).
   - `first_epss`: Exploit Prediction Scoring System probability score (0.000 to 1.000).
   - `reference_url`: Canonical NIST NVD advisory URL for provenance tracing.
   - `source_snapshot_date`: Fixed point-in-time evaluation snapshot timestamp.

2. **`profiles.json`** (6 Organizational Contexts):
   - **`ORG-001` Global Retail Bank**: Financial Services · Low Risk Appetite · Core Banking (`internet-facing`, `critical`).
   - **`ORG-002` Agile Cloud Tech Startup**: Technology · High Risk Appetite · Cloud SaaS API (`internet-facing`, `high`).
   - **`ORG-003` Municipal Utility Provider**: Critical Infrastructure · Zero-Tolerance · SCADA Telemetry (`internal`, `critical`).
   - **`ORG-004` Apex Global Logistics (Profile D)`**: Transportation & Supply Chain · Moderate Risk · Fleet Telematics (`internet-facing`, `critical`).
   - **`ORG-005` Synthetic Zero-Match (Profile E)`**: Experimental Research · Low Risk · Quantum Simulator (`internal`, `normal`).
   - **`ORG-006` Helios Health**: Digital Health & Life Sciences · Low Risk · Patient Portal Gateway (`internet-facing`, `critical`).
   - *Profile fields:* `org_id`, `name`, `sector`, `risk_appetite`, `service`, `exposure`, `importance`, `weight_modifiers` (`cvss_weight`, `cisa_kev_weight`, `first_epss_weight`), `technologies[]` (`vendor`, `product`, `version`), and `critical_products[]`.

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
  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────────┐
  │ INCLUDE_RANK │  │   EXCLUDE    │  │ INCLUDE_NEEDS_VERIFICATION│
  └──────────────┘  └──────────────┘  └───────────────────────────┘
```

### The Three Outcomes:
1. **`INCLUDE_RANK` (In Scope)**:
   - The product and vendor match the organization's technology stack (exact or alias-resolved), AND the installed version is proven to fall within the affected range (`version_start` to `version_end`).
   - Fully scored, eligible for Top 5 actionable queue.
2. **`INCLUDE_NEEDS_VERIFICATION`**:
   - The product matches the organization's inventory, but the version boundary cannot be mathematically proven (e.g. version missing in profile inventory, advisory specifies `version_note`, or matched via fuzzy token overlap).
   - Scored with a calibrated confidence penalty (-0.05 / -0.10) to avoid false security while ensuring analyst review.
3. **`EXCLUDE`**:
   - The software is **not present** in the organization's inventory, OR the installed version is **proven outside** the vulnerable boundary (e.g., running patched `v11.0` when affected is `< 10.0`).
   - Excluded records are accompanied by an auditable `exclusion_reason`.

### Alias Canonicalization Table
Common industry naming variations are normalized deterministically (e.g. `httpd` -> `http_server`, `wp` -> `wordpress`, `nodejs framework` -> `nodejs`, `expressjs web engine` -> `express`, `microsoft corp` -> `microsoft`).

### Semantic Version Comparison
Versions are compared chunk-by-chunk using integer tuples, cleanly handling partial semver (e.g., `2.4.49` vs `2.4.50`, `6.1` vs `6.0`, `11.0` vs `10.0`). Non-standard version strings safely fall back to `INCLUDE_NEEDS_VERIFICATION`.

### Deduplication Guarantee
Input rows are strictly deduplicated by the composite key `(cve_id, product_name)` before ranking, ensuring every CVE-product pair is evaluated exactly once with zero double-counting.

---

## 3. Ranking & Scoring Logic

The scoring engine evaluates the formula:

$$\text{Score} = \left(\frac{\text{CVSS}}{10}\right) \times W_{\text{CVSS}} + \text{KEV} \times W_{\text{KEV}} + \text{EPSS} \times W_{\text{EPSS}} + \text{Exposure Bonus} + \text{Importance Bonus} - \text{Confidence Penalty}$$

### Term Definitions:
- **CVSS Base Score ($\frac{\text{CVSS}}{10} \times W_{\text{CVSS}}$)**: Technical severity normalized from 0.0 to 1.0.
- **CISA KEV ($\text{KEV} \times W_{\text{KEV}}$)**: Binary flag (1.0 or 0.0) indicating active exploitation in the wild.
- **First EPSS ($\text{EPSS} \times W_{\text{EPSS}}$)**: Exploit Prediction Scoring System probability (0.000 to 1.000).
- **Asset Exposure Bonus**:
  - `internet-facing` service -> **+0.20**
  - `internal` service -> **+0.05**
- **Asset Importance Bonus**:
  - `critical` asset -> **+0.15**
  - `high` asset -> **+0.10**
  - `normal` asset -> **+0.05**
- **Confidence Penalty**:
  - `INCLUDE_NEEDS_VERIFICATION` (unverified version) -> **-0.05**
  - `Fuzzy Match` (>= 70% similarity) -> **-0.10**

### Priority Bands & Operational Directives:
- **URGENT** (>= 0.70): Immediate escalation and remediation window. High exploitation threat to critical assets. (Action: *Patch / Escalate*)
- **HIGH** (0.50 - 0.69): Scheduled sprint remediation. Confirmed vulnerability on active software stack. (Action: *Patch*)
- **WATCH** (0.30 - 0.49): Internal exposure or unexploited flaws requiring proactive monitoring. (Action: *Review Guidance / Restrict*)
- **BASELINE** (< 0.30): Standard patching cycle. Low probability of exploitation on non-critical service. (Action: *Monitor*)

---

## 4. Negative Testing & Ground-Truth Validation

- **Featured CVSS >= 9.0 Negative Test**: The Overview page prominently highlights high-severity CVEs (e.g. `CVE-2026-1769`, CVSS 9.4) that are rightfully excluded from an organisation's remediation queue because the product does not match active asset inventory, demonstrating defense against alert fatigue.
- **Zero-Match Handling**: For unrepresented profiles (e.g., Profile E), TriageCN outputs the exact verified state: *"Nothing matched this profile in the supplied data."* rather than fabricating artificial rankings.

---

## 5. Data Sources & Attribution

- **Vulnerability Datasets**: Vulnerability data is sourced from NIST's National Vulnerability Database (NVD), CISA's Known Exploited Vulnerabilities (KEV) catalog, and FIRST's Exploit Prediction Scoring System (EPSS), used under each source's respective public usage terms.
- **Static Demonstration Snapshot**: This is a static, frozen snapshot for demonstration purposes — not a live feed — and is not officially affiliated with, endorsed by, or representing NIST, CISA, or FIRST.
- **Synthetic Fictional Profiles**: All organisation profiles (Global Retail Bank, Agile Cloud Tech Startup, Municipal Utility Provider, Profile D, Profile E, Helios Health) are entirely fictional and synthetic; no real organisations, real vulnerabilities-in-context, or personal data are represented.

---

## 6. Scope & Ethical Use Disclaimer

- **Defensive Triage Aid Only**: This prototype is a defensive prioritization tool designed solely to assist security analysts. It reports which known vulnerabilities match a stated technology profile — it never claims an organisation is secure, immune, or vulnerability-free.
- **Zero Scanning / Probing**: No scanning, probing, or live testing of any network or software system occurs. No exploit code is included, executed, or generated.
- **Zero Personal Data**: No personal identifiable information (PII) is collected, stored, processed, or displayed anywhere in the application.

---

## 7. Assumptions & Known Limitations

### Assumptions:
1. **Version Format**: Versions in profiles and CVE records follow standard semantic versioning (`major.minor.patch`) or clean numeric prefixes.
2. **Deterministic Aliases**: Canonical alias mappings cover standard software catalog variations.
3. **Point-in-Time Snapshot**: Data represents the evaluation snapshot timestamp; dynamic external updates require refreshing the local CSV dataset.

### Known Limitations:
1. **Semantic Versioning Boundary**: Version comparison assumes clean semantic versioning. Non-standard or vendor-specific version formats are safely routed to **Needs Verification** with a calibrated confidence penalty (-0.05) rather than being auto-matched or erroneously excluded, ensuring defensive analyst review.
2. **Static Local Snapshot**: Designed exclusively for offline zero-network execution without live external enrichment or background network callbacks.

---

## 8. Quick Setup Guide (< 5 Minutes)

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

## 9. License

MIT License. Designed and developed for the Nexora 2k26 Hackathon.
