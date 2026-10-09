# PolicyGuard — Policy-to-Control Mapping & Continuous Compliance Platform

**PolicyGuard** is an enterprise-grade prototype for continuous security compliance and governance. It bridges the critical gap between high-level written security policies and low-level technical enforcement telemetry.

```
USER UPLOADS POLICY
        ↓
TEXT EXTRACTION (PDF, DOCX, TXT)
        ↓
POLICY ANALYSIS & METADATA DETECTION
        ↓
REQUIREMENT EXTRACTION (Deterministic + Optional Claude AI)
        ↓
HUMAN REVIEW / APPROVAL (Governance Gate)
        ↓
CONTROL MAPPING (NIST SP 800-53, ISO 27001:2022, CIS Controls)
        ↓
AUTOMATED CHECK SELECTION (Check Registry: R1–R4)
        ↓
COMPLIANCE EXECUTION (Simulated Identity & Access Telemetry)
        ↓
TELEMETRY / AUDIT EVIDENCE
        ↓
COMPLIANCE RESULT (GREEN / AMBER / RED Posture)
        ↓
RISK / FINDINGS & REMEDIATION (Automated Re-Testing)
        ↓
DASHBOARD / EXPORT REPORTS (CSV & JSON)
```

> **IMPORTANT DISCLAIMER:**
> - All identity and HR account data used in this platform is **simulated sample data** (`sample_data/accounts.csv`). It is not sourced from a live production enterprise.
> - Framework mappings (NIST SP 800-53, ISO/IEC 27001:2022, CIS Controls) are **educational project crosswalks**, not official or certified compliance accreditations.

---

## 1. Governance Architecture: Policy to Remediation

The core lifecycle implemented by PolicyGuard:

1. **Policy**: High-level governance statements (e.g. *"Privileged accounts must use multi-factor authentication"*).
2. **Requirement**: Normalized, measurable technical requirement statements with defined metric, threshold, and data source.
3. **Control**: Concrete control specification mapped to standard frameworks (NIST, ISO 27001, CIS).
4. **Automated Check**: Deterministic probe configured in the check registry (`check_registry.py`).
5. **Telemetry**: Raw evidence feeds (simulated from identity provider, HR feeds, ticket logs).
6. **Compliance**: Calculated adherence percentages with risk thresholds (GREEN: 100%, AMBER: >= amber threshold, RED: below threshold).
7. **Finding**: Actionable defect record for each non-compliant identity or resource.
8. **Remediation**: Assigned task workflow (owner, due date, action); resolving a task automatically triggers compliance re-evaluation.

---

## 2. Key Features

- **Dynamic Policy Upload**:
  - Drag-and-drop intake supporting **PDF**, **DOCX**, and **TXT** documents.
  - Safe extraction without execution; strictly enforced 10 MB file size limit and extension validation.
  - Automatic metadata detection: Policy Name, Version, Owner, Effective Date, Review Date, Policy Category.
  - Policy categories supported: *Access Control*, *Authentication / Password*, *Account Management*, *Data Protection*, *Logging and Monitoring*.
- **Human-in-the-Loop Governance Gate**:
  - Extracted requirements and control mappings are **never automatically approved**.
  - Analysts must explicitly review, edit, approve, or reject candidate items.
- **Rule-Based & Optional AI Extraction**:
  - Deterministic governance rule-based pattern extractor covers MFA, access reviews, leavers, dormant accounts, logging, and encryption.
  - Optional Anthropic Claude integration via `ANTHROPIC_API_KEY` (clearly labeled *"AI Suggested"* with *"AI suggestions require analyst validation"*).
- **Check Registry & Engine Reuse**:
  - Reuses the proven Python continuous compliance engine (`checks.py`, `data_source.py`, `config.py`).
  - Mapped automated checks:
    - **R1 Admin MFA**: 100% of privileged accounts have MFA enabled.
    - **R2 Access Reviews**: 100% of admin accounts reviewed within 90 days.
    - **R3 Leaver Removal**: 100% of departed personnel disabled within 24 hours.
    - **R4 Dormant Accounts**: No active accounts without login activity for > 45 days.
- **Findings & Remediation Lifecycle**:
  - Non-compliant accounts generate prioritized risk findings.
  - Remediation tasks can be assigned with owners and deadlines.
  - Resolving a remediation task triggers automatic re-evaluation of compliance posture.
- **Audit Logging & Reporting**:
  - Immutable audit trail recording uploads, reviews, approvals, executions, and remediations.
  - Audit-ready CSV and JSON downloads.
- **Interactive "What-If" Simulator**:
  - Preserves the original slider-based threshold sensitivity simulator.

---

## 3. Project Structure

```
compliance_project/
├── app/
│   ├── main.py                    # FastAPI server & REST API
│   ├── policy_upload.py           # Safe document upload handler
│   ├── policy_parser.py           # TXT, PDF, DOCX extraction & metadata detection
│   ├── requirement_extractor.py   # Rule-based & optional Claude AI extractor
│   ├── mapping_engine.py          # Framework mapping engine
│   ├── check_registry.py          # Automated probe registry (R1–R4 integration)
│   ├── storage.py                 # Local JSON persistence & audit logger
│   └── models.py                  # Pydantic data schemas
├── dashboard/
│   └── templates/
│       └── index.html             # Professional dark security dashboard
├── mappings/
│   └── framework_mappings.json    # Educational framework crosswalks
├── sample_data/
│   ├── accounts.csv               # Simulated identity accounts dataset (60 accounts)
│   └── sample_access_control_policy.txt # Built-in demo policy document
├── tests/
│   ├── test_checks.py             # Existing unit tests for R1-R4
│   ├── test_policy_guard.py       # New platform unit tests
│   └── verify_demo_flow.py        # End-to-end 13-step workflow verification script
├── checks.py                      # Original compliance check logic (preserved)
├── config.py                      # Original thresholds and controls (preserved)
├── data_source.py                 # Original data loading & generator (preserved)
├── report.py                      # Original report & HTML dashboard generator (preserved)
├── dashboard_template.html        # Original what-if template (preserved)
├── run_compliance_check.py        # Original CLI runner (preserved)
├── requirements.txt               # Dependencies
├── .env.example                   # Environment configuration example
├── README.md                      # Platform documentation
└── INTERVIEW_NOTES.md             # Interview walkthrough & Q&A guide
```

---

## 4. Installation & Setup

### Prerequisites
- Python 3.8+ (Python 3.10 recommended)
- `pip`

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

*(Installed packages: `fastapi`, `uvicorn`, `python-multipart`, `pypdf`, `python-docx`, `pydantic`, `httpx`)*

### Step 2 (Optional): Configure AI Assistance
Copy `.env.example` to `.env` and set your Anthropic API key if desired:
```bash
cp .env.example .env
```
*Note: If no API key is provided, PolicyGuard operates completely offline using deterministic governance rule-based extraction.*

---

## 5. Running the Application

### Option A: Launch PolicyGuard Web Platform (FastAPI + Dashboard)
Run the server with Uvicorn:
```bash
python -m uvicorn app.main:app --reload --port 8000
```
Open your browser at:
👉 **`http://127.0.0.1:8000`**

### Option B: Run Existing Baseline CLI
The original command line continuous compliance checker remains 100% functional:
```bash
python run_compliance_check.py
```
*(Use `--no-open` to prevent automatic browser launch).*

---

## 6. End-to-End Demo Workflow (13 Steps)

1. **Open Platform**: Navigate to `http://127.0.0.1:8000`.
2. **Upload Policy**: Click **"Upload Security Policy"** and drag `sample_data/sample_access_control_policy.txt` (or click **"Load Built-in Demo Policy"**).
3. **Text Extraction**: Text is extracted safely and metadata is identified (Policy Name, Version 3.2, Owner, Effective Date, Access Control category).
4. **Candidate Requirements**: 4 candidate requirements are generated (MFA, Access Review, Leaver Removal, Dormant Accounts).
5. **Human Review**: In the **Requirements** tab, review suggested metrics and thresholds; click **[Approve]** on each requirement.
6. **Control Mapping**: Navigate to the **Controls** tab; verify mappings to NIST SP 800-53, ISO 27001, and CIS Controls; click **[Approve]** on each control.
7. **Run Compliance**: Click **"Run Compliance Checks"**; the engine executes R1–R4 checks against `accounts.csv`.
8. **Inspect Posture**: Observe the overall compliance score and GREEN / AMBER / RED status cards.
9. **Failing Accounts**: Scroll down to view the flagged non-compliant accounts table.
10. **Evidence Catalog**: Click the **Evidence** tab to inspect simulated telemetry records with timestamp and data source details.
11. **Create Remediation**: Click **"Create Task"** on a finding to assign an owner, priority, and deadline.
12. **Resolve & Re-test**: In the **Exceptions** tab, click **"Mark Resolved"** to simulate fixing the account; the compliance check automatically re-evaluates.
13. **Export Reports**: In the **Reports** tab, download the full compliance report in **CSV** or **JSON**.

---

## 7. Running Tests

Run all unit tests across the original checks and the new platform:
```bash
python -m unittest discover tests
```
Run the complete end-to-end demo flow verification script:
```bash
python tests/verify_demo_flow.py
```

---

## 8. Security Considerations

- **Untrusted File Ingestion**: Uploaded documents are treated as untrusted data. Files are never executed or evaluated dynamically.
- **Strict Size and Type Validation**: Strictly rejects files larger than 10 MB and restricts extensions to `.pdf`, `.docx`, and `.txt`.
- **Safe Filenames**: Random UUIDs and sanitized stems prevent path traversal attacks.
- **Zero Hardcoded Secrets**: Secrets such as `ANTHROPIC_API_KEY` are read exclusively from environment variables.
- **Human-in-the-Loop Governance**: AI suggestions and rule extractions never auto-promote to production enforcement without explicit human approval.

---

## 9. Limitations

- **Simulated Telemetry**: Feeds are read from local CSV files; real enterprise production deployments would integrate via REST APIs with Microsoft Entra ID / Okta, Workday, and Jira/ServiceNow.
- **Educational Framework Crosswalks**: NIST, ISO, and CIS mappings are illustrative project baselines and must be validated against official publications.
- **Single Host Storage**: State is persisted locally in `data_store/policyguard_db.json`. High-scale deployments would use PostgreSQL or DynamoDB.
