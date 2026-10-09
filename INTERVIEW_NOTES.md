# PolicyGuard: Interview & Demonstration Notes

A complete guide to presenting, explaining, and defending **PolicyGuard** in cybersecurity, GRC (Governance, Risk, and Compliance), and engineering interviews.

---

## 1. 30-Second Elevator Pitch

> *"PolicyGuard solves the disconnect between static security policies and dynamic technical reality. An analyst uploads a written policy (PDF, DOCX, or TXT), from which the system extracts measurable candidate requirements and maps them to NIST SP 800-53, ISO 27001, and CIS Controls. After a mandatory human approval gate, PolicyGuard binds those requirements to automated continuous telemetry probes (like Admin MFA, access reviews, leaver removal, and dormant accounts) running against identity feeds. It calculates live compliance scores, flags non-compliant accounts, catalogs audit evidence, and drives remediation workflows with automated re-testing."*

---

## 2. 2-Minute Demonstration Script

1. **Start with the Core Problem**:
   *"Security policies usually sit in SharePoint PDFs while engineers configure IAM in consoles. Audits happen once a year by sampling 20 accounts. PolicyGuard makes policy actionable and compliance continuous."*
2. **Step 1 — Upload Policy**:
   Click **"Upload Security Policy"** (or **"Load Built-in Demo Policy"**). Show the metadata extraction: Name, Version, Owner, Effective Date, and Category.
3. **Step 2 — Candidate Requirements & Governance Gate**:
   Open the **Requirements** tab:
   *"Notice these requirements are labeled 'Candidate'. Governance systems must never autonomously enforce obligations. The analyst verifies the metric (e.g. 100% Admin MFA) and clicks [Approve]."*
4. **Step 3 — Control Mapping**:
   Open the **Controls** tab:
   *"Approved requirements map to educational crosswalks in NIST SP 800-53, ISO 27001, and CIS Controls, binding to specific automated probes in our check registry."*
5. **Step 4 — Continuous Compliance Execution**:
   Click **"Run Compliance Checks"**:
   *"The engine tests accounts against our four core controls (R1–R4). R1 flags admin user015 without MFA; R3 flags departed staff still active; R4 flags dormant accounts."*
6. **Step 5 — Audit Evidence & Remediation**:
   Show the **Evidence** tab:
   *"Every run produces immutable audit evidence with timestamps and source systems."*
   Open **Findings**, click **"Create Task"**, and then mark it **"Resolved"** in the **Exceptions** tab:
   *"When remediation is marked complete, the compliance engine automatically re-evaluates posture and updates the score without waiting for an annual audit."*

---

## 3. Architecture Explanation

PolicyGuard follows a clean, decoupled 4-tier architecture:

```
┌────────────────────────────────────────────────────────┐
│                   Web Presentation Layer               │
│     FastAPI + Dark Cyber Dashboard + Interactive DOM   │
└───────────────────────────▲────────────────────────────┘
                            │ REST API
┌───────────────────────────▼────────────────────────────┐
│                    Governance Engine                   │
│   • policy_upload.py (Safe Intake, PDF/DOCX/TXT)      │
│   • policy_parser.py (Regex Metadata & Taxonomy)       │
│   • requirement_extractor.py (Rules + Optional AI)    │
│   • mapping_engine.py (NIST/ISO/CIS Knowledge Base)    │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│               Continuous Compliance Engine             │
│   • check_registry.py (Probe Bindings & Orchestration) │
│   • checks.py (R1 Admin MFA, R2 Reviews, R3 Leavers...)│
│   • storage.py (JSON Persistence, Audit Logging)       │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                   Simulated Telemetry                  │
│   • data_source.py (Identity Provider & HR Feeds)      │
│   • sample_data/accounts.csv                           │
└────────────────────────────────────────────────────────┘
```

---

## 4. Why Human Approval is Required (Human-in-the-Loop)

- **Governance is Legal & Regulatory, Not Algorithmic**: Automatically turning an AI or regex extraction into an enforced technical control could misinterpret legal policy intent or disrupt production operations.
- **Analyst Validation Prevents Hallucination & Scope Creep**: An AI might mistake an aspirational guideline (*"teams should consider encrypting..."*) for a mandatory blocking control (*"must encrypt with AES-256"*).
- **Audit Defensibility**: External auditors (SOC 2, ISO, FedRAMP) require human accountability for control design and scoping decisions.

---

## 5. How AI is Used

- **Assistive, Never Authoritative**: AI (Anthropic Claude via `ANTHROPIC_API_KEY`) is purely optional. If omitted, deterministic rule-based matching runs offline.
- **Scoped to Analysis & Drafting**: AI parses unstructured natural language policy paragraphs, normalizes them into atomic requirement statements, and suggests relevant framework citations.
- **Explicit Labeling**: Every AI output is tagged with `"AI Suggested"` and accompanied by the UI disclaimer: *"AI suggestions require analyst validation."*

---

## 6. How Policy Becomes a Control

```
Policy Statement:
"Privileged accounts must use multi-factor authentication."
       ↓
Requirement Specification (REQ-001):
• Category: Access Control
• Target: Privileged users (is_admin == True)
• Metric: MFA Coverage %
• Threshold: 100%
       ↓
Control Specification (R1):
• NIST SP 800-53: IA-2(1), AC-6
• ISO/IEC 27001:2022: A.8.5, A.8.2
• CIS Controls: CIS 5.2, CIS 6.1
• Telemetry Field: mfa_enabled == TRUE
• Frequency: Daily
       ↓
Automated Probe (check_r1):
• Filters enabled admins in accounts.csv
• Returns non-compliant accounts
```

---

## 7. How Compliance is Measured

$$\text{Compliance } \% = \frac{\text{Accounts in Scope} - \text{Non-Compliant Accounts}}{\text{Accounts in Scope}} \times 100$$

- **GREEN**: 100% adherence (zero defect tolerance for mandatory controls).
- **AMBER**: High compliance, but minor exceptions (e.g. $\ge 98\%$ for MFA, $\ge 95\%$ for access reviews).
- **RED**: Below the amber risk threshold. Represents an immediate audit finding.

---

## 8. What "Telemetry" Means in this Project

In enterprise security, **telemetry** refers to observable system data emitted by infrastructure and applications:
- **Identity Provider Telemetry**: User account status (`enabled`), MFA registration (`mfa_enabled`), last interactive authentication timestamp (`last_login_date`).
- **HR Telemetry**: Separation effective date (`terminated_on`), offboarding ticket timestamp.
- **Governance Tool Telemetry**: Last periodic entitlement recertification date (`last_review_date`).

In this project, telemetry is simulated via structured records in `sample_data/accounts.csv`, providing realistic evaluation data without exposing live production credentials.

---

## 9. How Continuous Compliance Works

- **Traditional Audit**: Once every 12 months, auditors pull a sample of 25 accounts. A departing employee whose account stayed open for 6 months might never be sampled.
- **Continuous Compliance**: Automated probes evaluate **100% of accounts every single day**. When an employee leaves, if their account is still active after 24 hours, an alert and finding are generated immediately. Compliance posture is tracked dynamically over time.

---

## 10. How this Integrates with Real Identity Providers

In an enterprise environment, `data_source.py` would be replaced with API connectors:
1. **Microsoft Entra ID (Azure AD) / Okta**: Graph API queries (`GET /v1.0/users?$select=userPrincipalName,accountEnabled,signInActivity`) to pull MFA status and last sign-in.
2. **Workday / BambooHR**: Daily leaver report via HR API or webhook on termination event.
3. **SailPoint / Saviynt / Jira**: Access review completion records.
4. **SIEM (Splunk / Datadog / Sentinel)**: Audit log retention and security event streaming.

---

## 11. Known Limitations

1. **Simulated Dataset**: Uses local CSV accounts rather than active OAuth2 identity directory APIs.
2. **Four Automated Controls**: Built specifically for identity and access management (IAM); other domains (e.g. vulnerability management, DLP) require custom probes.
3. **Single Host Storage**: State is persisted in local JSON (`data_store/policyguard_db.json`).
4. **Educational Framework Crosswalks**: NIST, ISO, and CIS IDs are illustrative and must be verified against official authoritative catalogs.

---

## 12. Top 10 Likely Interviewer Questions & Model Answers

### Q1: Why did you separate requirement extraction from control mapping?
> *"Because a single policy requirement often maps to multiple regulatory frameworks simultaneously. For example, 'Privileged accounts must use MFA' addresses NIST IA-2(1), ISO 27001 A.8.5, CIS 5.2, and PCI-DSS 8.3. Keeping requirements atomic allows many-to-many crosswalking without duplicating governance logic."*

### Q2: Why not let an LLM write executable Python code to run the checks dynamically?
> *"Generating arbitrary executable code from an LLM in a production governance system introduces severe security and reliability risks: code injection, unexpected side effects, and lack of test coverage. Instead, we use a curated **Check Registry** (`check_registry.py`) with vetted, pre-tested Python probes, allowing AI only to recommend bindings."*

### Q3: What happens if an uploaded policy is ambiguous or contradicts itself?
> *"The deterministic extractor flags confidence as 'Low' and marks the requirement as 'Candidate' or 'Needs Review'. In our UI, the human analyst can edit the threshold or reject the requirement before it ever touches a control."*

### Q4: How do you handle service accounts or break-glass admin accounts that legitimately cannot use standard MFA?
> *"In production, we introduce an **Exceptions / Exclusions** workflow. An account can have an approved, time-bounded exception ticket with risk sign-off and compensating controls (e.g. PAM vaulting, IP restrictions, alert on use). The compliance check filters out approved active exceptions."*

### Q5: How do you prevent false positives in leaver detection?
> *"By correlating two independent sources of truth: the HR termination timestamp and the directory account status. A finding is only raised if `terminated_on` is populated and either the account remains enabled or the disable latency exceeds the policy threshold (e.g. 24 hours)."*

### Q6: Why did you choose FastAPI over Flask or Django?
> *"FastAPI provides native asynchronous endpoints, automatic Pydantic request/response validation, automatic OpenAPI documentation, and high performance via Starlette and Uvicorn with minimal boilerplate."*

### Q7: How does resolving a remediation task update the compliance percentage?
> *"Our remediation endpoint implements an event-driven workflow: when a remediation task is marked 'Resolved', the platform immediately re-triggers the compliance engine against the target account, re-calculating in-scope compliance percentages, updating finding states, and recording an audit log entry."*

### Q8: What is the risk of relying solely on rule-based extraction?
> *"Rule-based pattern matching requires regular maintenance of keyword dictionaries. However, in security governance, deterministic consistency is an advantage: policy authors use standardized modal verbs ('must', 'shall', 'required'). Our hybrid model gives deterministic baseline reliability with optional AI flexibility."*

### Q9: How would this scale to hundreds of policies and thousands of controls?
> *"The architecture is stateless at the API layer. We would migrate `storage.py` to PostgreSQL with Prisma/SQLAlchemy, run continuous checks asynchronously via Celery or AWS Lambda on a cron schedule, and partition evidence records by policy ID and tenant."*

### Q10: How does this map to the GRID framework / Security Governance & Risk roles?
> *"PolicyGuard directly models the Governance, Risk, and Internal Control lifecycle: Policy formulation $\rightarrow$ Technical control design $\rightarrow$ Continuous effectiveness testing $\rightarrow$ Deficiency identification (Findings) $\rightarrow$ Corrective Action Plans (Remediation) $\rightarrow$ Audit trail for regulatory assurance."*
