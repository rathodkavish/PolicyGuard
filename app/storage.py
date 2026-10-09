"""Local JSON storage for PolicyGuard platform."""
import json
import os
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.models import Policy, Requirement, ControlMapping, Finding, RemediationTask, EvidenceItem, AuditLogEntry

STORE_DIR = Path(__file__).resolve().parent.parent / "data_store"
STORE_FILE = STORE_DIR / "policyguard_db.json"


class StorageManager:
    def __init__(self, store_file: Path = STORE_FILE):
        self.store_file = store_file
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.store_file.exists():
            self._init_db()

    def _init_db(self):
        initial = {
            "policies": {},
            "requirements": {},
            "mappings": {},
            "findings": {},
            "remediations": {},
            "evidence": {},
            "audit_logs": [],
            "last_compliance_run": None,
            "compliance_summary": {}
        }
        self._write(initial)

    def _read(self) -> Dict[str, Any]:
        try:
            with open(self.store_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "policies": {},
                "requirements": {},
                "mappings": {},
                "findings": {},
                "remediations": {},
                "evidence": {},
                "audit_logs": [],
                "last_compliance_run": None,
                "compliance_summary": {}
            }

    def _write(self, data: Dict[str, Any]):
        temp_file = self.store_file.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_file.replace(self.store_file)

    # --- Audit Log ---
    def log_audit(self, action: str, object_name: str, result: str, user: str = "Analyst (Current User)", details: str = None) -> AuditLogEntry:
        entry = AuditLogEntry(
            id=f"AUD-{uuid.uuid4().hex[:6].upper()}",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user=user,
            action=action,
            object=object_name,
            result=result,
            details=details
        )
        data = self._read()
        data["audit_logs"].insert(0, entry.model_dump())
        # Cap audit logs to last 500
        data["audit_logs"] = data["audit_logs"][:500]
        self._write(data)
        return entry

    def list_audit_logs(self, limit: int = 100) -> List[AuditLogEntry]:
        data = self._read()
        return [AuditLogEntry(**item) for item in data.get("audit_logs", [])[:limit]]

    # --- Policies ---
    def save_policy(self, policy: Policy) -> Policy:
        data = self._read()
        data["policies"][policy.policy_id] = policy.model_dump()
        self._write(data)
        self.log_audit("Policy uploaded", f"Policy {policy.policy_id} ({policy.name})", "Success")
        return policy

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        data = self._read()
        raw = data.get("policies", {}).get(policy_id)
        return Policy(**raw) if raw else None

    def list_policies(self) -> List[Policy]:
        data = self._read()
        return [Policy(**raw) for raw in data.get("policies", {}).values()]

    def update_policy_status(self, policy_id: str, new_status: str) -> Optional[Policy]:
        data = self._read()
        if policy_id in data.get("policies", {}):
            data["policies"][policy_id]["status"] = new_status
            self._write(data)
            self.log_audit("Policy status updated", f"Policy {policy_id}", f"Status: {new_status}")
            return Policy(**data["policies"][policy_id])
        return None

    def update_policy_category(self, policy_id: str, category: str) -> Optional[Policy]:
        data = self._read()
        if policy_id in data.get("policies", {}):
            data["policies"][policy_id]["category"] = category
            self._write(data)
            self.log_audit("Policy category updated", f"Policy {policy_id}", f"Category: {category}")
            return Policy(**data["policies"][policy_id])
        return None

    # --- Requirements ---
    def save_requirements(self, reqs: List[Requirement]):
        data = self._read()
        for r in reqs:
            data["requirements"][r.requirement_id] = r.model_dump()
        self._write(data)

    def get_requirement(self, req_id: str) -> Optional[Requirement]:
        data = self._read()
        raw = data.get("requirements", {}).get(req_id)
        return Requirement(**raw) if raw else None

    def list_requirements(self, policy_id: Optional[str] = None) -> List[Requirement]:
        data = self._read()
        reqs = [Requirement(**raw) for raw in data.get("requirements", {}).values()]
        if policy_id:
            reqs = [r for r in reqs if r.policy_id == policy_id]
        return reqs

    def update_requirement(self, req_id: str, updates: Dict[str, Any]) -> Optional[Requirement]:
        data = self._read()
        if req_id in data.get("requirements", {}):
            data["requirements"][req_id].update(updates)
            self._write(data)
            action = "Requirement updated"
            if "status" in updates:
                action = f"Requirement {updates['status'].lower()}"
            self.log_audit(action, f"Requirement {req_id}", "Success", details=str(updates))
            return Requirement(**data["requirements"][req_id])
        return None

    # --- Control Mappings ---
    def save_mappings(self, mappings: List[ControlMapping]):
        data = self._read()
        for m in mappings:
            data["mappings"][m.mapping_id] = m.model_dump()
        self._write(data)
        for m in mappings:
            self.log_audit("Control mapped", f"Mapping {m.mapping_id} (Control {m.control_id})", "Success")

    def get_mapping(self, mapping_id: str) -> Optional[ControlMapping]:
        data = self._read()
        raw = data.get("mappings", {}).get(mapping_id)
        return ControlMapping(**raw) if raw else None

    def list_mappings(self, policy_id: Optional[str] = None) -> List[ControlMapping]:
        data = self._read()
        maps = [ControlMapping(**raw) for raw in data.get("mappings", {}).values()]
        if policy_id:
            maps = [m for m in maps if m.policy_id == policy_id]
        return maps

    def update_mapping(self, mapping_id: str, updates: Dict[str, Any]) -> Optional[ControlMapping]:
        data = self._read()
        if mapping_id in data.get("mappings", {}):
            data["mappings"][mapping_id].update(updates)
            self._write(data)
            action = "Mapping updated"
            if "status" in updates:
                action = f"Mapping {updates['status'].lower()}"
            self.log_audit(action, f"Mapping {mapping_id}", "Success", details=str(updates))
            return ControlMapping(**data["mappings"][mapping_id])
        return None

    # --- Compliance Results & Findings ---
    def save_compliance_execution(self, summary: Dict[str, Any], findings: List[Finding], evidence: List[EvidenceItem]):
        data = self._read()
        data["last_compliance_run"] = datetime.now().isoformat()
        data["compliance_summary"] = summary
        
        # update findings: add new or retain resolved
        existing_findings = data.get("findings", {})
        for f in findings:
            # if exists and was resolved or accepted, keep status unless user requested re-eval
            if f.finding_id in existing_findings and existing_findings[f.finding_id].get("status") in ("Resolved", "Accepted Risk"):
                continue
            existing_findings[f.finding_id] = f.model_dump()
        data["findings"] = existing_findings

        # save evidence items
        ev_dict = data.get("evidence", {})
        for ev in evidence:
            ev_dict[ev.evidence_id] = ev.model_dump()
        data["evidence"] = ev_dict

        # update mappings effectiveness
        for res in summary.get("results", []):
            cid = res.get("id")
            pct = res.get("compliance_pct", 0)
            st = res.get("status", "RED")
            for mid, mdata in data.get("mappings", {}).items():
                if mdata.get("control_id") == cid:
                    mdata["latest_result"] = f"{pct}% ({st})"
                    mdata["effectiveness"] = "Effective" if st == "GREEN" else ("Partially Effective" if st == "AMBER" else "Deficient")

        self._write(data)
        self.log_audit("Compliance check executed", f"Executed {len(summary.get('results', []))} controls", f"Overall: {summary.get('overall_pct', 0)}%")

    def get_compliance_summary(self) -> Dict[str, Any]:
        data = self._read()
        return {
            "last_run": data.get("last_compliance_run"),
            "summary": data.get("compliance_summary", {}),
            "open_findings_count": len([f for f in data.get("findings", {}).values() if f.get("status") == "Open"]),
            "open_remediations_count": len([r for r in data.get("remediations", {}).values() if r.get("status") == "Open"])
        }

    # --- Findings ---
    def list_findings(self, policy_id: Optional[str] = None) -> List[Finding]:
        data = self._read()
        findings = [Finding(**raw) for raw in data.get("findings", {}).values()]
        if policy_id:
            findings = [f for f in findings if f.policy_id == policy_id]
        return findings

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        data = self._read()
        raw = data.get("findings", {}).get(finding_id)
        return Finding(**raw) if raw else None

    def update_finding(self, finding_id: str, updates: Dict[str, Any]) -> Optional[Finding]:
        data = self._read()
        if finding_id in data.get("findings", {}):
            data["findings"][finding_id].update(updates)
            self._write(data)
            self.log_audit("Finding updated", f"Finding {finding_id}", updates.get("status", "Updated"))
            return Finding(**data["findings"][finding_id])
        return None

    # --- Remediation Tasks ---
    def save_remediation(self, task: RemediationTask) -> RemediationTask:
        data = self._read()
        data["remediations"][task.task_id] = task.model_dump()
        # link to finding
        if task.finding_id in data.get("findings", {}):
            data["findings"][task.finding_id]["remediation_task_id"] = task.task_id
            data["findings"][task.finding_id]["status"] = "In Progress"
        self._write(data)
        self.log_audit("Remediation created", f"Task {task.task_id} for Finding {task.finding_id}", "Open", details=task.description)
        return task

    def list_remediations(self) -> List[RemediationTask]:
        data = self._read()
        return [RemediationTask(**raw) for raw in data.get("remediations", {}).values()]

    def resolve_remediation(self, task_id: str) -> Optional[RemediationTask]:
        data = self._read()
        if task_id in data.get("remediations", {}):
            task_data = data["remediations"][task_id]
            task_data["status"] = "Resolved"
            task_data["resolved_at"] = datetime.now().isoformat()
            
            # Also resolve associated finding
            fid = task_data.get("finding_id")
            if fid and fid in data.get("findings", {}):
                data["findings"][fid]["status"] = "Resolved"

            self._write(data)
            self.log_audit("Remediation completed", f"Task {task_id}", "Resolved", details="Finding marked resolved")
            return RemediationTask(**task_data)
        return None

    # --- Evidence ---
    def list_evidence(self, policy_id: Optional[str] = None) -> List[EvidenceItem]:
        data = self._read()
        evs = [EvidenceItem(**raw) for raw in data.get("evidence", {}).values()]
        if policy_id:
            evs = [e for e in evs if e.policy_id == policy_id]
        return evs


db = StorageManager()
