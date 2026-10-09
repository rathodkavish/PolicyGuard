"""Requirement extraction engine: Rule-based deterministic extractor with optional Claude AI assistance."""
import os
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.models import Requirement

# Optional Anthropic API integration
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()


def extract_requirements_rule_based(policy_text: str, policy_id: str) -> List[Requirement]:
    """Deterministic rule-based requirement extractor based on security governance patterns."""
    requirements: List[Requirement] = []
    req_counter = 1

    # Split text into sentences / bullet points / lines
    # Normalize line breaks and split by sentence or bullet
    raw_units = []
    for line in policy_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Split on bullet points or strong sentence ends
        parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])|•|[-*]\s+", line)
        for p in parts:
            p = p.strip()
            if len(p) >= 15:  # meaningful sentence or statement
                raw_units.append(p)

    # Patterns to match with corresponding requirement definitions
    RULE_DEFINITIONS = [
        {
            "id_suffix": "MFA",
            "keywords_all": [
                [r"\bmfa\b", r"multi-factor", r"two-factor", r"2fa"],
                [r"privileged", r"admin", r"administrative", r"user", r"account", r"credential"]
            ],
            "text": "Privileged accounts must use multi-factor authentication.",
            "category": "Access Control",
            "metric": "MFA compliance percentage",
            "threshold": "100% of admin accounts have MFA enabled",
            "data_source": "Identity provider, cloud IAM reports (accounts.csv)",
            "confidence": "High"
        },
        {
            "id_suffix": "REV",
            "keywords_all": [
                [r"review", r"reviewed", r"recertif", r"audit"],
                [r"access", r"privileged", r"admin", r"permission", r"role"],
                [r"90\s*days", r"quarter", r"regularly", r"periodic"]
            ],
            "text": "Privileged access must be reviewed regularly (every 90 days).",
            "category": "Access Control",
            "metric": "Access review compliance percentage",
            "threshold": "100% of admin accounts reviewed in last 90 days",
            "data_source": "Access review tool or ticket system (accounts.csv)",
            "confidence": "High"
        },
        {
            "id_suffix": "TERM",
            "keywords_all": [
                [r"terminat", r"leaver", r"depart", r"offboard", r"separated"],
                [r"disable", r"remove", r"revok", r"deprovision"],
                [r"24\s*hour", r"promptly", r"immediately", r"day"]
            ],
            "text": "Access of leavers must be removed promptly (within 24 hours).",
            "category": "Account Management",
            "metric": "Leaver removal compliance percentage",
            "threshold": "100% of leavers disabled within 24 hours",
            "data_source": "HR system and identity provider (accounts.csv)",
            "confidence": "High"
        },
        {
            "id_suffix": "DORM",
            "keywords_all": [
                [r"dormant", r"inactive", r"unused", r"without activity", r"no login"],
                [r"account", r"user", r"credential"],
                [r"45\s*days", r"30\s*days", r"60\s*days", r"days", r"review", r"disable"]
            ],
            "text": "Unused/dormant accounts must be identified and reviewed (over 45 days).",
            "category": "Account Management",
            "metric": "Dormant account compliance percentage",
            "threshold": "No enabled account without login for over 45 days",
            "data_source": "Identity provider (accounts.csv)",
            "confidence": "High"
        },
        {
            "id_suffix": "LOG",
            "keywords_all": [
                [r"audit\s*log", r"logging", r"telemetry", r"audit\s*trail"],
                [r"retain", r"centraliz", r"monitor", r"protect", r"siem"]
            ],
            "text": "Centralized audit logs must be enabled and retained for all security-relevant events.",
            "category": "Logging and Monitoring",
            "metric": "Log retention compliance percentage",
            "threshold": ">= 365 days retention for security events",
            "data_source": "SIEM / Central Log Repository",
            "confidence": "Medium"
        },
        {
            "id_suffix": "ENC",
            "keywords_all": [
                [r"encrypt", r"cryptograph"],
                [r"at\s*rest", r"in\s*transit", r"data\s*protection", r"sensitive"]
            ],
            "text": "Sensitive corporate and customer data must be encrypted using approved cryptographic standards.",
            "category": "Data Protection",
            "metric": "Storage encryption percentage",
            "threshold": "100% sensitive storage volumes encrypted",
            "data_source": "Cloud asset configuration inventory",
            "confidence": "Medium"
        }
    ]

    matched_suffixes = set()

    for unit in raw_units:
        unit_lower = unit.lower()
        for rule in RULE_DEFINITIONS:
            if rule["id_suffix"] in matched_suffixes:
                continue

            # Verify all required keyword groups match
            matches_all_groups = True
            for group in rule["keywords_all"]:
                group_matched = any(re.search(kw, unit_lower) for kw in group)
                if not group_matched:
                    matches_all_groups = False
                    break

            if matches_all_groups:
                req_id = f"REQ-{req_counter:03d}"
                req_counter += 1
                matched_suffixes.add(rule["id_suffix"])

                requirements.append(
                    Requirement(
                        requirement_id=req_id,
                        policy_id=policy_id,
                        text=rule["text"],
                        source_snippet=unit.strip(),
                        category=rule["category"],
                        metric=rule["metric"],
                        threshold=rule["threshold"],
                        data_source=rule["data_source"],
                        confidence=rule["confidence"],
                        status="Candidate",  # ALWAYS Candidate; never auto-approved
                        ai_suggested=False,
                        explanation="Extracted via deterministic governance pattern matching."
                    )
                )

    # General catch-all for modal verbs ("must", "shall", "required to") if no specific rule matched
    if not requirements:
        for unit in raw_units:
            if re.search(r"\b(must|shall|is required to|mandatory)\b", unit, re.IGNORECASE):
                req_id = f"REQ-{req_counter:03d}"
                req_counter += 1
                requirements.append(
                    Requirement(
                        requirement_id=req_id,
                        policy_id=policy_id,
                        text=unit.strip(),
                        source_snippet=unit.strip(),
                        category="Access Control",
                        metric="Policy compliance verification",
                        threshold="100% adherence to policy directive",
                        data_source="Manual audit / System configuration",
                        confidence="Low",
                        status="Candidate",
                        ai_suggested=False,
                        explanation="Generic obligation statement identified by modal verb."
                    )
                )
                if len(requirements) >= 5:
                    break

    return requirements


def extract_requirements_ai(policy_text: str, policy_id: str, api_key: str) -> List[Requirement]:
    """Optional Claude AI-assisted extraction if ANTHROPIC_API_KEY is configured."""
    try:
        import httpx
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        prompt = f"""You are a security governance and compliance expert.
Analyze the following security policy text and extract measurable candidate requirements.
For each requirement, provide JSON output matching this schema:
[
  {{
    "text": "Clear measurable statement",
    "source_snippet": "Exact sentence or snippet from text",
    "category": "Access Control | Authentication / Password | Account Management | Data Protection | Logging and Monitoring",
    "metric": "Measurable telemetry metric",
    "threshold": "Measurable threshold value",
    "data_source": "Suggested system of record (e.g. Identity provider, HR system, SIEM)",
    "confidence": "High | Medium | Low",
    "explanation": "Why this requirement was extracted"
  }}
]
Only output valid JSON array, nothing else.

Policy Text:
{policy_text[:4000]}
"""
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = httpx.post(url, headers=headers, json=payload, timeout=20.0)
        if resp.status_code == 200:
            content = resp.json()["content"][0]["text"]
            # Extract JSON block
            json_match = re.search(r"\[\s*\{.*\}\s*\]", content, re.DOTALL)
            if json_match:
                raw_reqs = json.loads(json_match.group(0))
                results = []
                for idx, r in enumerate(raw_reqs, start=1):
                    results.append(
                        Requirement(
                            requirement_id=f"REQ-{idx:03d}",
                            policy_id=policy_id,
                            text=r.get("text", "Requirement"),
                            source_snippet=r.get("source_snippet", ""),
                            category=r.get("category", "Access Control"),
                            metric=r.get("metric", "Adherence %"),
                            threshold=r.get("threshold", "100%"),
                            data_source=r.get("data_source", "IAM / Logs"),
                            confidence=r.get("confidence", "Medium"),
                            status="Candidate",  # ALWAYS Candidate; never auto-approved
                            ai_suggested=True,
                            explanation=f"AI Suggested: {r.get('explanation', 'Model extracted requirement.')}"
                        )
                    )
                return results
    except Exception as e:
        # Fall back to rule-based on any AI failure
        pass
    return []


def extract_requirements(policy_text: str, policy_id: str) -> List[Requirement]:
    """Unified entry point: tries Claude if key is set, falls back to deterministic rule-based."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        ai_reqs = extract_requirements_ai(policy_text, policy_id, api_key)
        if ai_reqs:
            return ai_reqs

    return extract_requirements_rule_based(policy_text, policy_id)
