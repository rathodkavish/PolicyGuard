"""Check Registry: Integrates with existing R1-R4 checks and executes compliance engine."""
import uuid
from pathlib import Path
from datetime import date, datetime
from typing import List, Dict, Any, Optional, Tuple

import checks
import config
import data_source
from app.models import ControlMapping, Finding, EvidenceItem, ComplianceResult

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_ACCOUNTS_CSV = BASE_DIR / "sample_data" / "accounts.csv"

# Registered checks dictionary
CHECK_REGISTRY = {
    "R1": {
        "id": "R1",
        "name": "Administrative Multi-Factor Authentication",
        "description": "Verify all privileged/administrative accounts have MFA enabled.",
        "data_source_name": "Sample Identity Account Dataset (sample_data/accounts.csv)",
        "field": "mfa_enabled",
        "expected_value": "TRUE",
        "metric": "MFA Coverage %",
        "threshold": "100%",
        "amber_threshold": 98,
        "frequency": "Daily",
        "severity": "High",
        "check_func": checks.check_r1,
        "simulated": True
    },
    "R2": {
        "id": "R2",
        "name": "Periodic Privileged Access Review",
        "description": "Ensure privileged accounts are reviewed within the mandatory window (90 days).",
        "data_source_name": "Access Review Tool / Ticket System (sample_data/accounts.csv)",
        "field": "last_review_date",
        "expected_value": "<= 90 days",
        "metric": "Access Review Compliance %",
        "threshold": "100% within 90 days",
        "amber_threshold": 95,
        "frequency": "Weekly",
        "severity": "Medium",
        "check_func": checks.check_r2,
        "simulated": True
    },
    "R3": {
        "id": "R3",
        "name": "Terminated Personnel Access Revocation (Leaver Removal)",
        "description": "Verify departing staff accounts are disabled within 24 hours.",
        "data_source_name": "HR System & Identity Provider Feed (sample_data/accounts.csv)",
        "field": "disabled_after_hours",
        "expected_value": "<= 24 hours",
        "metric": "Leaver Removal Compliance %",
        "threshold": "100% disabled within 24 hours",
        "amber_threshold": 95,
        "frequency": "Daily",
        "severity": "High",
        "check_func": checks.check_r3,
        "simulated": True
    },
    "R4": {
        "id": "R4",
        "name": "Inactive / Dormant Account Management",
        "description": "Detect enabled accounts without any login activity for over 45 days.",
        "data_source_name": "Identity Provider Directory (sample_data/accounts.csv)",
        "field": "last_login_date",
        "expected_value": "<= 45 days",
        "metric": "Dormant Account Compliance %",
        "threshold": "No enabled account without login > 45 days",
        "amber_threshold": 95,
        "frequency": "Daily",
        "severity": "Medium",
        "check_func": checks.check_r4,
        "simulated": True
    }
}


def get_check_definition(check_id: str) -> Optional[Dict[str, Any]]:
    return CHECK_REGISTRY.get(check_id)


def execute_compliance(
    approved_mappings: List[ControlMapping],
    accounts_csv_path: Optional[Path] = None,
    threshold_overrides: Optional[Dict[str, int]] = None,
    as_of: Optional[date] = None,
    resolved_finding_accounts: Optional[List[str]] = None
) -> Tuple[Dict[str, Any], List[Finding], List[EvidenceItem]]:
    """
    Executes approved automated checks against the dataset.
    Returns: (summary_dict, new_findings, evidence_items)
    """
    if as_of is None:
        as_of = date.today()

    data_path = accounts_csv_path or DEFAULT_ACCOUNTS_CSV
    if not data_path.exists():
        data_path.parent.mkdir(parents=True, exist_ok=True)
        data_source.generate_sample_csv(data_path, as_of)

    accounts = data_source.load_accounts(data_path, as_of)
    
    # If any accounts were marked resolved in remediation, simulate resolution in current run
    resolved_set = set(resolved_finding_accounts or [])
    if resolved_set:
        for a in accounts:
            if a["account"] in resolved_set:
                a["mfa"] = True
                a["review_days"] = min(a["review_days"], 30)
                if a["left"]:
                    a["enabled"] = False
                    a["disabled_after_hours"] = 2
                a["login_days"] = min(a["login_days"], 15)

    thresholds = dict(config.THRESHOLDS)
    if threshold_overrides:
        thresholds.update(threshold_overrides)

    results = []
    findings: List[Finding] = []
    evidence_items: List[EvidenceItem] = []

    # Map approved controls to their corresponding automated checks
    executed_check_ids = set()
    total_pct_sum = 0.0
    control_count = 0

    now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for mapping in approved_mappings:
        check_id = mapping.automated_check_id
        if not check_id or check_id not in CHECK_REGISTRY:
            # Manual validation required control
            results.append({
                "id": mapping.control_id,
                "name": mapping.control_name,
                "policy_id": mapping.policy_id,
                "requirement_id": mapping.requirement_id,
                "requirement_text": mapping.metric,
                "mapping": mapping.nist_mapping + mapping.iso_mapping + mapping.cis_mapping,
                "in_scope": 0,
                "non_compliant": 0,
                "compliance_pct": 100.0,
                "status": "GREEN",
                "manual": True,
                "note": "Manual validation required — no automated telemetry probe configured.",
                "exceptions": []
            })
            continue

        chk_def = CHECK_REGISTRY[check_id]
        check_fn = chk_def["check_func"]
        
        in_scope, bad_list = check_fn(accounts, thresholds)
        non_compliant_count = len(bad_list)
        pct = 100.0 * (in_scope - non_compliant_count) / in_scope if in_scope else 100.0
        pct = round(pct, 1)
        st = checks.status(pct, chk_def["amber_threshold"])

        total_pct_sum += pct
        control_count += 1

        exceptions = [{"account": a, "finding": f} for a, f in bad_list]

        results.append({
            "id": mapping.control_id,
            "check_id": check_id,
            "name": mapping.control_name,
            "policy_id": mapping.policy_id,
            "requirement_id": mapping.requirement_id,
            "requirement_text": mapping.threshold,
            "mapping": mapping.nist_mapping + mapping.iso_mapping + mapping.cis_mapping,
            "in_scope": in_scope,
            "non_compliant": non_compliant_count,
            "compliance_pct": pct,
            "status": st,
            "manual": False,
            "exceptions": exceptions
        })

        # Generate Evidence item
        ev_id = f"EV-{uuid.uuid4().hex[:6].upper()}"
        evidence_items.append(
            EvidenceItem(
                evidence_id=ev_id,
                policy_id=mapping.policy_id,
                requirement_id=mapping.requirement_id,
                control_id=mapping.control_id,
                check_id=check_id,
                timestamp=now_ts,
                data_source=chk_def["data_source_name"],
                result=f"{pct}% Compliant ({in_scope - non_compliant_count}/{in_scope} compliant, {non_compliant_count} failing)",
                finding=f"{non_compliant_count} failing accounts identified: {', '.join([a for a, _ in bad_list[:5]])}" if bad_list else "0 findings detected.",
                sample_notice="Simulated evidence generated from project sample data."
            )
        )

        # Generate Findings for non-compliant accounts
        for acct_id, detail in bad_list:
            find_id = f"FIND-{mapping.control_id}-{acct_id}"
            sev = chk_def["severity"]
            desc = f"{chk_def['name']}: Account {acct_id} is non-compliant ({detail})."
            findings.append(
                Finding(
                    finding_id=find_id,
                    policy_id=mapping.policy_id,
                    requirement_id=mapping.requirement_id,
                    control_id=mapping.control_id,
                    account=acct_id,
                    severity=sev,
                    description=desc,
                    detected_at=now_ts,
                    status="Open"
                )
            )

    overall_pct = round(total_pct_sum / control_count, 1) if control_count > 0 else 100.0
    summary = {
        "execution_date": as_of.isoformat(),
        "timestamp": now_ts,
        "data_source": data_path.name,
        "controls_evaluated": len(results),
        "overall_pct": overall_pct,
        "green_count": len([r for r in results if r["status"] == "GREEN"]),
        "amber_count": len([r for r in results if r["status"] == "AMBER"]),
        "red_count": len([r for r in results if r["status"] == "RED"]),
        "thresholds_used": thresholds,
        "results": results
    }

    return summary, findings, evidence_items
