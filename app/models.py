"""Data models and schemas for PolicyGuard platform."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Policy(BaseModel):
    policy_id: str
    name: str
    filename: str
    category: str = "Access Control"
    version: str = "Not detected"
    owner: str = "Not detected"
    effective_date: str = "Not detected"
    review_date: str = "Not detected"
    uploaded_at: str
    status: str = "Draft"  # Draft -> Under Review -> Approved -> Published -> Active -> Review -> Retired
    file_path: Optional[str] = None
    raw_text: str = ""
    word_count: int = 0
    extraction_status: str = "Success"


class Requirement(BaseModel):
    requirement_id: str
    policy_id: str
    text: str
    source_snippet: str
    category: str
    metric: str
    threshold: str
    data_source: str
    confidence: str = "High"  # High, Medium, Low
    status: str = "Candidate"  # Candidate, Approved, Rejected, Needs Review
    ai_suggested: bool = False
    explanation: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ControlMapping(BaseModel):
    mapping_id: str
    control_id: str
    control_name: str
    policy_id: str
    requirement_id: str
    nist_mapping: List[str] = []
    iso_mapping: List[str] = []
    cis_mapping: List[str] = []
    metric: str
    threshold: str
    data_source: str
    automated_check_id: Optional[str] = None
    automated_check_name: str = "Manual validation required"
    field: Optional[str] = None
    expected_value: Optional[str] = None
    frequency: str = "Daily"
    status: str = "Candidate"  # Candidate, Approved, Rejected
    effectiveness: str = "Pending Execution"  # Effective, Deficient, Pending Execution
    latest_result: Optional[str] = None  # e.g. "92.3% (RED)"
    ai_suggested: bool = False
    ai_explanation: Optional[str] = None


class ComplianceResult(BaseModel):
    control_id: str
    requirement_text: str
    in_scope: int
    non_compliant: int
    compliance_pct: float
    status: str
    exceptions: List[Dict[str, Any]] = []
    execution_time: Optional[str] = None


class Finding(BaseModel):
    finding_id: str
    policy_id: str
    requirement_id: str
    control_id: str
    account: str
    severity: str = "High"  # High, Medium, Low
    description: str
    detected_at: str
    status: str = "Open"  # Open, In Progress, Resolved, Accepted Risk
    remediation_task_id: Optional[str] = None


class RemediationTask(BaseModel):
    task_id: str
    finding_id: str
    control_id: str
    owner: str
    priority: str = "High"  # High, Medium, Low
    due_date: str
    description: str
    status: str = "Open"  # Open, In Progress, Resolved
    created_at: str
    resolved_at: Optional[str] = None


class EvidenceItem(BaseModel):
    evidence_id: str
    policy_id: str
    requirement_id: str
    control_id: str
    check_id: str
    timestamp: str
    data_source: str
    result: str
    finding: str
    sample_notice: str = "Simulated evidence generated from project sample data."


class AuditLogEntry(BaseModel):
    id: str
    timestamp: str
    user: str = "Analyst (Current User)"
    action: str
    object: str
    result: str
    details: Optional[str] = None
