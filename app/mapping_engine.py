"""Framework mapping engine: Maps approved requirements to NIST, ISO 27001, and CIS controls."""
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.models import Requirement, ControlMapping

MAPPINGS_FILE = Path(__file__).resolve().parent.parent / "mappings" / "framework_mappings.json"


class MappingEngine:
    def __init__(self, mappings_file: Path = MAPPINGS_FILE):
        self.mappings_file = mappings_file
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> List[Dict[str, Any]]:
        if not self.mappings_file.exists():
            return []
        try:
            with open(self.mappings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("mappings", [])
        except Exception:
            return []

    def map_requirement(self, requirement: Requirement) -> ControlMapping:
        """Deterministically map an approved requirement to standard framework controls."""
        text = (requirement.text + " " + requirement.source_snippet).lower()
        
        # Match against knowledge base
        matched_kb = None
        for item in self.knowledge_base:
            k = item.get("key", "").lower()
            if k == "mfa" and ("mfa" in text or "multi-factor" in text or "2fa" in text):
                matched_kb = item
                break
            elif k == "access_review" and ("review" in text or "recertif" in text or "90 days" in text):
                matched_kb = item
                break
            elif k == "leaver_removal" and ("terminat" in text or "leaver" in text or "depart" in text or "24 hours" in text):
                matched_kb = item
                break
            elif k == "dormant_accounts" and ("dormant" in text or "inactive" in text or "without activity" in text or "45 days" in text or "unused" in text):
                matched_kb = item
                break
            elif k == "audit_logging" and ("log" in text or "audit" in text or "telemetry" in text):
                matched_kb = item
                break
            elif k == "encryption_at_rest" and ("encrypt" in text or "cryptograph" in text or "pii" in text):
                matched_kb = item
                break

        mapping_id = f"MAP-{requirement.requirement_id}"

        if matched_kb:
            return ControlMapping(
                mapping_id=mapping_id,
                control_id=matched_kb["control_id"],
                control_name=matched_kb["control_name"],
                policy_id=requirement.policy_id,
                requirement_id=requirement.requirement_id,
                nist_mapping=matched_kb.get("nist_mapping", []),
                iso_mapping=matched_kb.get("iso_mapping", []),
                cis_mapping=matched_kb.get("cis_mapping", []),
                metric=matched_kb.get("metric", requirement.metric),
                threshold=matched_kb.get("threshold", requirement.threshold),
                data_source=matched_kb.get("data_source", requirement.data_source),
                automated_check_id=matched_kb.get("automated_check_id"),
                automated_check_name=matched_kb.get("automated_check_name", "Manual validation required"),
                field=matched_kb.get("field"),
                expected_value=matched_kb.get("expected_value"),
                frequency=matched_kb.get("frequency", "Daily"),
                status="Candidate",  # Must be approved by human
                effectiveness="Pending Execution",
                ai_suggested=False,
                ai_explanation="Mapped via vetted educational framework knowledge base."
            )
        else:
            # Generic fallback control mapping
            return ControlMapping(
                mapping_id=mapping_id,
                control_id=f"CTL-{requirement.requirement_id}",
                control_name=f"Control for {requirement.text[:40]}...",
                policy_id=requirement.policy_id,
                requirement_id=requirement.requirement_id,
                nist_mapping=["NIST AC-1", "NIST PL-2"],
                iso_mapping=["ISO/IEC 27001:2022 A.5.1"],
                cis_mapping=["CIS Control 1.1"],
                metric=requirement.metric,
                threshold=requirement.threshold,
                data_source=requirement.data_source,
                automated_check_id=None,
                automated_check_name="Manual validation required",
                field="policy_compliance",
                expected_value="TRUE",
                frequency="Monthly",
                status="Candidate",
                effectiveness="Pending Execution",
                ai_suggested=False,
                ai_explanation="Educational generic governance baseline mapping. Requires human analyst validation."
            )

    def generate_mappings_for_requirements(self, requirements: List[Requirement]) -> List[ControlMapping]:
        """Generate mappings for a list of requirements."""
        return [self.map_requirement(r) for r in requirements]


mapping_engine = MappingEngine()
