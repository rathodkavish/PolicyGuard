"""End-to-end demo flow verification script."""
import sys
from pathlib import Path
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.main import app

def run_verification():
    client = TestClient(app)

    # 1. Health check
    res = client.get("/api/health")
    assert res.status_code == 200, res.text
    print("Step 1: Health check passed ->", res.json()["status"])

    # 2. Upload / load demo policy
    res = client.post("/api/policies/demo")
    assert res.status_code == 200, res.text
    demo_data = res.json()
    pol_id = demo_data["policy"]["policy_id"]
    print(f"Step 2: Demo policy loaded -> {pol_id}")

    # 3. Check requirements
    res = client.get("/api/requirements")
    reqs = res.json()
    print(f"Step 3: Extracted {len(reqs)} candidate requirements")
    assert len(reqs) >= 4

    # 4. Approve requirements
    for r in reqs:
        rid = r["requirement_id"]
        res = client.post(f"/api/requirements/{rid}/approve")
        assert res.status_code == 200
    print("Step 4: All candidate requirements approved")

    # 5. Check & approve mappings
    res = client.get("/api/mappings")
    mappings = res.json()
    print(f"Step 5: {len(mappings)} candidate control mappings generated")
    for m in mappings:
        mid = m["mapping_id"]
        res = client.post(f"/api/mappings/{mid}/approve")
        assert res.status_code == 200
    print("Step 6: All candidate control mappings approved")

    # 6. Run continuous compliance
    res = client.post("/api/compliance/run")
    assert res.status_code == 200, res.text
    comp = res.json()
    overall = comp["summary"]["overall_pct"]
    print(f"Step 7: Compliance run executed -> Overall Compliance: {overall}%")

    # 7. Check findings
    res = client.get("/api/findings")
    findings = res.json()
    print(f"Step 8: Non-compliance findings created -> {len(findings)} findings")
    assert len(findings) > 0

    # 8. Create remediation task for a finding
    target_f = findings[0]
    rem_payload = {
        "finding_id": target_f["finding_id"],
        "owner": "Identity and Access Operations Team",
        "priority": "High",
        "due_date": "2026-10-16",
        "description": "Enforce MFA for user account in IdP directory"
    }
    res = client.post("/api/remediations", json=rem_payload)
    assert res.status_code == 200, res.text
    rem_task = res.json()
    task_id = rem_task["task_id"]
    print(f"Step 9: Remediation task created -> {task_id}")

    # 9. Resolve remediation task and re-test
    res = client.post(f"/api/remediations/{task_id}/resolve")
    assert res.status_code == 200, res.text
    print("Step 10: Remediation task marked Resolved -> Automatic compliance re-evaluation triggered")

    # 10. Check evidence
    res = client.get("/api/evidence")
    ev = res.json()
    print(f"Step 11: Audit evidence catalog items recorded -> {len(ev)} items")
    assert len(ev) >= 4

    # 11. Reports (CSV and JSON)
    res_csv = client.get("/api/reports/csv")
    assert res_csv.status_code == 200
    assert "POLICYGUARD COMPREHENSIVE COMPLIANCE REPORT" in res_csv.text

    res_json = client.get("/api/reports/json")
    assert res_json.status_code == 200
    assert "report_title" in res_json.json()
    print("Step 12: Audit reports generated successfully (CSV & JSON)")

    # 12. Check audit logs
    res_audit = client.get("/api/audit-logs")
    logs = res_audit.json()
    print(f"Step 13: System audit log trail verified -> {len(logs)} audit entries recorded")
    assert len(logs) >= 5

    print("\nSUCCESS: All 13 steps of the end-to-end PolicyGuard workflow verified perfectly!")

if __name__ == "__main__":
    run_verification()
