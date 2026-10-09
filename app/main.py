"""FastAPI application entry point for PolicyGuard platform."""
import os
import io
import csv
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, date

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.models import Policy, Requirement, ControlMapping, Finding, RemediationTask, EvidenceItem
from app.storage import db
from app.policy_upload import handle_policy_upload
from app.policy_parser import SUPPORTED_CATEGORIES
from app.requirement_extractor import extract_requirements
from app.mapping_engine import mapping_engine
from app.check_registry import execute_compliance, CHECK_REGISTRY, DEFAULT_ACCOUNTS_CSV
import config
import checks
import data_source
import report

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "dashboard" / "templates"
STATIC_DIR = BASE_DIR / "dashboard" / "static"
SAMPLE_POLICY_PATH = BASE_DIR / "sample_data" / "sample_access_control_policy.txt"

app = FastAPI(
    title="PolicyGuard",
    description="Policy-to-Control Mapping & Continuous Compliance Platform",
    version="2.0.0"
)

# Mount static files if directory exists
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Pydantic request models for updating entities
class RequirementUpdateRequest(BaseModel):
    status: Optional[str] = None  # Approved, Rejected, Candidate, Needs Review
    text: Optional[str] = None
    metric: Optional[str] = None
    threshold: Optional[str] = None
    data_source: Optional[str] = None
    confidence: Optional[str] = None


class MappingUpdateRequest(BaseModel):
    status: Optional[str] = None  # Approved, Rejected, Candidate
    control_name: Optional[str] = None
    nist_mapping: Optional[List[str]] = None
    iso_mapping: Optional[List[str]] = None
    cis_mapping: Optional[List[str]] = None
    metric: Optional[str] = None
    threshold: Optional[str] = None
    data_source: Optional[str] = None
    frequency: Optional[str] = None


class FindingStatusRequest(BaseModel):
    status: str  # Open, In Progress, Resolved, Accepted Risk


class RemediationCreateRequest(BaseModel):
    finding_id: str
    owner: str
    priority: str = "High"
    due_date: str
    description: str


class PolicyStatusRequest(BaseModel):
    status: str


class PolicyCategoryRequest(BaseModel):
    category: str


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": "PolicyGuard",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }


# --- Policies ---
@app.get("/api/policies")
def list_policies():
    return db.list_policies()


@app.get("/api/policies/{policy_id}")
def get_policy(policy_id: str):
    pol = db.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    return pol


@app.post("/api/policies/upload")
async def upload_policy(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_policy.txt"
    content = await file.read()
    success, msg, data = handle_policy_upload(filename, content)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg, "policy": data}


@app.post("/api/policies/demo")
def load_demo_policy():
    """Loads the built-in demonstration Access Control Policy."""
    if not SAMPLE_POLICY_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample policy text file not found.")
    content = SAMPLE_POLICY_PATH.read_bytes()
    success, msg, data = handle_policy_upload("sample_access_control_policy.txt", content)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    
    # Auto-extract candidate requirements for the demo policy so the user immediately sees them
    pol_id = data["policy_id"]
    reqs = extract_requirements(data["raw_text"], pol_id)
    db.save_requirements(reqs)

    # Generate candidate control mappings for these requirements
    mappings = mapping_engine.generate_mappings_for_requirements(reqs)
    db.save_mappings(mappings)

    return {
        "message": "Demo policy loaded and analyzed successfully with candidate requirements & mappings.",
        "policy": data,
        "requirements_count": len(reqs),
        "mappings_count": len(mappings)
    }


@app.put("/api/policies/{policy_id}/status")
def update_policy_status(policy_id: str, req: PolicyStatusRequest):
    updated = db.update_policy_status(policy_id, req.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Policy not found")
    return updated


@app.put("/api/policies/{policy_id}/category")
def update_policy_category(policy_id: str, req: PolicyCategoryRequest):
    updated = db.update_policy_category(policy_id, req.category)
    if not updated:
        raise HTTPException(status_code=404, detail="Policy not found")
    return updated


# --- Requirements ---
@app.post("/api/policies/{policy_id}/extract-requirements")
def extract_policy_requirements(policy_id: str):
    pol = db.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    reqs = extract_requirements(pol.raw_text, policy_id)
    db.save_requirements(reqs)

    # Also generate candidate mappings immediately so human reviewer can see suggestions
    mappings = mapping_engine.generate_mappings_for_requirements(reqs)
    db.save_mappings(mappings)

    db.log_audit("Requirement extraction executed", f"Policy {policy_id}", f"Extracted {len(reqs)} candidate requirements")
    return {
        "policy_id": policy_id,
        "requirements": reqs,
        "mappings": mappings
    }


@app.get("/api/requirements")
def list_requirements(policy_id: Optional[str] = None):
    return db.list_requirements(policy_id)


@app.put("/api/requirements/{req_id}")
def update_requirement(req_id: str, req: RequirementUpdateRequest):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = db.update_requirement(req_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Requirement not found")
    
    # If approved, ensure matching control mapping is updated or available
    if updates.get("status") == "Approved":
        existing_mappings = db.list_mappings()
        has_mapping = any(m.requirement_id == req_id for m in existing_mappings)
        if not has_mapping:
            mapping = mapping_engine.map_requirement(updated)
            db.save_mappings([mapping])

    return updated


@app.post("/api/requirements/{req_id}/approve")
def approve_requirement(req_id: str):
    return update_requirement(req_id, RequirementUpdateRequest(status="Approved"))


@app.post("/api/requirements/{req_id}/reject")
def reject_requirement(req_id: str):
    return update_requirement(req_id, RequirementUpdateRequest(status="Rejected"))


# --- Control Mappings ---
@app.get("/api/mappings")
def list_mappings(policy_id: Optional[str] = None):
    return db.list_mappings(policy_id)


@app.put("/api/mappings/{mapping_id}")
def update_mapping(mapping_id: str, req: MappingUpdateRequest):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = db.update_mapping(mapping_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return updated


@app.post("/api/mappings/{mapping_id}/approve")
def approve_mapping(mapping_id: str):
    return update_mapping(mapping_id, MappingUpdateRequest(status="Approved"))


@app.post("/api/mappings/{mapping_id}/reject")
def reject_mapping(mapping_id: str):
    return update_mapping(mapping_id, MappingUpdateRequest(status="Rejected"))


# --- Continuous Compliance Engine ---
@app.post("/api/compliance/run")
def run_compliance_check_api(policy_id: Optional[str] = None):
    """
    Executes approved automated checks.
    Only approved controls can be used for compliance execution.
    """
    all_mappings = db.list_mappings(policy_id)
    approved_mappings = [m for m in all_mappings if m.status == "Approved"]

    if not approved_mappings:
        return {
            "status": "warning",
            "message": "No approved controls available to execute. Please review and approve requirements and control mappings first.",
            "results": [],
            "overall_pct": 0.0
        }

    # Retrieve accounts with resolved findings to reflect remediation
    remediations = db.list_remediations()
    resolved_accounts = []
    for r in remediations:
        if r.status == "Resolved":
            f = db.get_finding(r.finding_id)
            if f:
                resolved_accounts.append(f.account)

    summary, findings, evidence = execute_compliance(
        approved_mappings=approved_mappings,
        resolved_finding_accounts=resolved_accounts
    )

    db.save_compliance_execution(summary, findings, evidence)

    # Sync with existing root reports in output/ for backward compatibility!
    try:
        out_dir = BASE_DIR / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        report.write_outputs(summary["results"], out_dir)
        dash_path = out_dir / "dashboard.html"
        accounts = data_source.load_accounts(DEFAULT_ACCOUNTS_CSV, date.today())
        report.build_dashboard(
            BASE_DIR / "dashboard_template.html",
            dash_path,
            accounts,
            config.CONTROLS,
            config.THRESHOLDS,
            date.today(),
            DEFAULT_ACCOUNTS_CSV.name
        )
    except Exception as e:
        print(f"Notice: Root report sync: {e}")

    return {
        "status": "success",
        "message": f"Successfully executed continuous compliance check across {len(summary['results'])} controls.",
        "summary": summary,
        "findings_generated": len(findings),
        "evidence_generated": len(evidence)
    }


@app.get("/api/compliance/summary")
def get_compliance_summary():
    return db.get_compliance_summary()


# --- Findings & Remediation ---
@app.get("/api/findings")
def list_findings(policy_id: Optional[str] = None):
    return db.list_findings(policy_id)


@app.put("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: str, req: FindingStatusRequest):
    updated = db.update_finding(finding_id, {"status": req.status})
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return updated


@app.post("/api/remediations")
def create_remediation_task(req: RemediationCreateRequest):
    finding = db.get_finding(req.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    task_num = len(db.list_remediations()) + 1
    task_id = f"REM-{task_num:03d}"
    
    task = RemediationTask(
        task_id=task_id,
        finding_id=req.finding_id,
        control_id=finding.control_id,
        owner=req.owner,
        priority=req.priority,
        due_date=req.due_date,
        description=req.description,
        status="Open",
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.save_remediation(task)
    return task


@app.get("/api/remediations")
def list_remediations():
    return db.list_remediations()


@app.post("/api/remediations/{task_id}/resolve")
def resolve_remediation_task(task_id: str):
    resolved = db.resolve_remediation(task_id)
    if not resolved:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    
    # Automatically re-run compliance checks as per requirement 23:
    # "When marked resolved: re-run compliance check. Update: Finding, Control status, Compliance percentage, Dashboard, Audit log"
    all_mappings = db.list_mappings()
    approved_mappings = [m for m in all_mappings if m.status == "Approved"]
    if approved_mappings:
        remediations = db.list_remediations()
        resolved_accounts = []
        for r in remediations:
            if r.status == "Resolved":
                f = db.get_finding(r.finding_id)
                if f:
                    resolved_accounts.append(f.account)
        summary, findings, evidence = execute_compliance(
            approved_mappings=approved_mappings,
            resolved_finding_accounts=resolved_accounts
        )
        db.save_compliance_execution(summary, findings, evidence)

    return {
        "message": "Remediation task resolved and compliance checks re-evaluated.",
        "task": resolved
    }


# --- Evidence ---
@app.get("/api/evidence")
def list_evidence(policy_id: Optional[str] = None):
    return db.list_evidence(policy_id)


# --- Audit Logs ---
@app.get("/api/audit-logs")
def list_audit_logs():
    return db.list_audit_logs()


# --- Reports Export ---
@app.get("/api/reports/csv")
def download_csv_report():
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["POLICYGUARD COMPREHENSIVE COMPLIANCE REPORT"])
    writer.writerow(["Generated At", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow([])

    # Controls & Compliance Summary
    writer.writerow(["--- CONTROL COMPLIANCE POSTURE ---"])
    writer.writerow(["Control ID", "Control Name", "Requirement ID", "Framework Mappings", "Automated Probe", "In Scope", "Non-Compliant", "Compliance %", "Status", "Effectiveness"])
    mappings = db.list_mappings()
    summary = db.get_compliance_summary().get("summary", {})
    results_map = {r["id"]: r for r in summary.get("results", [])}

    for m in mappings:
        res = results_map.get(m.control_id, {})
        fw = "; ".join(m.nist_mapping + m.iso_mapping + m.cis_mapping)
        writer.writerow([
            m.control_id,
            m.control_name,
            m.requirement_id,
            fw,
            m.automated_check_id or "Manual",
            res.get("in_scope", "N/A"),
            res.get("non_compliant", "N/A"),
            f"{res.get('compliance_pct', 'N/A')}%" if "compliance_pct" in res else "Pending",
            res.get("status", "PENDING"),
            m.effectiveness
        ])
    
    writer.writerow([])
    # Findings
    writer.writerow(["--- NON-COMPLIANCE FINDINGS ---"])
    writer.writerow(["Finding ID", "Control ID", "Account / Resource", "Severity", "Description", "Detected At", "Status", "Remediation Task"])
    findings = db.list_findings()
    for f in findings:
        writer.writerow([f.finding_id, f.control_id, f.account, f.severity, f.description, f.detected_at, f.status, f.remediation_task_id or "None"])

    writer.writerow([])
    # Evidence
    writer.writerow(["--- AUDIT EVIDENCE CATALOG ---"])
    writer.writerow(["Evidence ID", "Control ID", "Timestamp", "Data Source", "Result Summary", "Finding Snippet", "Disclaimer"])
    for ev in db.list_evidence():
        writer.writerow([ev.evidence_id, ev.control_id, ev.timestamp, ev.data_source, ev.result, ev.finding, ev.sample_notice])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=policyguard_compliance_report.csv"}
    )


@app.get("/api/reports/json")
def download_json_report():
    summary_data = {
        "report_title": "PolicyGuard Continuous Compliance Report",
        "generated_at": datetime.now().isoformat(),
        "disclaimer": "Educational framework mappings and simulated telemetry from project sample data.",
        "policies": [p.model_dump() for p in db.list_policies()],
        "requirements": [r.model_dump() for r in db.list_requirements()],
        "controls": [m.model_dump() for m in db.list_mappings()],
        "compliance_summary": db.get_compliance_summary(),
        "findings": [f.model_dump() for f in db.list_findings()],
        "remediations": [rem.model_dump() for rem in db.list_remediations()],
        "evidence": [ev.model_dump() for ev in db.list_evidence()],
        "audit_logs": [aud.model_dump() for aud in db.list_audit_logs(limit=100)]
    }
    return JSONResponse(
        content=summary_data,
        headers={"Content-Disposition": "attachment; filename=policyguard_compliance_report.json"}
    )


# --- HTML Dashboard Views ---
@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>PolicyGuard is running. UI template not found.</h1>")


@app.get("/what-if", response_class=HTMLResponse)
def what_if_page():
    """Serves the original interactive what-if sliders dashboard."""
    dash_path = BASE_DIR / "output" / "dashboard.html"
    if dash_path.exists():
        return HTMLResponse(content=dash_path.read_text(encoding="utf-8"))
    template_path = BASE_DIR / "dashboard_template.html"
    if template_path.exists():
        accounts = data_source.load_accounts(DEFAULT_ACCOUNTS_CSV, date.today())
        dash_out = BASE_DIR / "output" / "dashboard.html"
        dash_out.parent.mkdir(parents=True, exist_ok=True)
        report.build_dashboard(template_path, dash_out, accounts, config.CONTROLS, config.THRESHOLDS, date.today(), DEFAULT_ACCOUNTS_CSV.name)
        return HTMLResponse(content=dash_out.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>What-if template not found</h1>")
