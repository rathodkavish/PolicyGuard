"""Unit tests for PolicyGuard: Upload, Extraction, Mapping, Governance, and Compliance Engine."""
import io
import sys
import unittest
from pathlib import Path
from datetime import date

# Ensure root workspace is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import checks
import config
import data_source
from app.models import Requirement, ControlMapping, Policy
from app.policy_parser import validate_file, extract_text_from_file, detect_metadata
from app.policy_upload import handle_policy_upload
from app.requirement_extractor import extract_requirements_rule_based
from app.mapping_engine import mapping_engine
from app.check_registry import execute_compliance, CHECK_REGISTRY
from app.storage import StorageManager


class TestPolicyGuard(unittest.TestCase):
    def setUp(self):
        # Use temporary storage for tests
        self.test_store_file = BASE_DIR / "data_store" / "test_policyguard_db.json"
        self.storage = StorageManager(self.test_store_file)
        self.test_storage_dir = BASE_DIR / "tests" / "test_artifacts"
        self.test_storage_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        # Clean up test database
        if self.test_store_file.exists():
            self.test_store_file.unlink()
        tmp = self.test_store_file.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()

    def test_file_validation(self):
        """Test safe file validation for formats and size limits."""
        ok, err = validate_file("policy.txt", 1024)
        self.assertTrue(ok)

        ok, err = validate_file("policy.pdf", 2048)
        self.assertTrue(ok)

        ok, err = validate_file("policy.docx", 4096)
        self.assertTrue(ok)

        # Invalid extension
        ok, err = validate_file("malicious.exe", 1024)
        self.assertFalse(ok)
        self.assertIn("Unsupported file format", err)

        # Exceeds 10 MB
        ok, err = validate_file("huge.pdf", 11 * 1024 * 1024)
        self.assertFalse(ok)
        self.assertIn("exceeds 10 MB", err)

    def test_txt_extraction_and_metadata(self):
        """Test text extraction and metadata detection from TXT document."""
        sample_txt = (
            "Policy Name: Global Access Control Policy\n"
            "Version: 2.4\n"
            "Owner: InfoSec Architecture Team\n"
            "Effective Date: 2026-01-01\n"
            "Review Date: 2026-12-31\n\n"
            "Privileged accounts must use multi-factor authentication.\n"
            "Administrative access must be reviewed every 90 days.\n"
        )
        txt_path = self.test_storage_dir / "sample.txt"
        txt_path.write_text(sample_txt, encoding="utf-8")

        extracted = extract_text_from_file(txt_path)
        self.assertIn("Global Access Control Policy", extracted)

        meta = detect_metadata(extracted, "sample.txt")
        self.assertEqual(meta["name"], "Global Access Control Policy")
        self.assertEqual(meta["version"], "v2.4")
        self.assertEqual(meta["owner"], "InfoSec Architecture Team")
        self.assertEqual(meta["effective_date"], "2026-01-01")
        self.assertEqual(meta["review_date"], "2026-12-31")
        self.assertEqual(meta["category"], "Access Control")

    def test_pdf_extraction(self):
        """Test extraction from PDF documents using pypdf."""
        import pypdf
        pdf_path = self.test_storage_dir / "test_doc.pdf"
        
        # Create a small valid PDF using pypdf writer
        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=200, height=200)
        # Note: blank page extracted text is empty or minimal, write and extract
        with open(pdf_path, "wb") as f:
            writer.write(f)

        extracted = extract_text_from_file(pdf_path)
        self.assertIsInstance(extracted, str)

    def test_docx_extraction(self):
        """Test extraction from DOCX documents using python-docx."""
        import docx
        doc_path = self.test_storage_dir / "test_doc.docx"
        doc = docx.Document()
        doc.add_heading("Policy Name: Cloud Security Policy", 0)
        doc.add_paragraph("Version: 1.0")
        doc.add_paragraph("All privileged users must use MFA.")
        doc.save(str(doc_path))

        extracted = extract_text_from_file(doc_path)
        self.assertIn("Cloud Security Policy", extracted)
        self.assertIn("All privileged users must use MFA", extracted)

    def test_requirement_extraction_rule_based(self):
        """Test deterministic rule-based requirement extraction across R1-R4 patterns."""
        policy_text = (
            "1. Privileged accounts must use multi-factor authentication (MFA).\n"
            "2. Administrative access must be reviewed regularly every 90 days.\n"
            "3. Terminated users must have access disabled within 24 hours.\n"
            "4. Enabled accounts without activity for more than 45 days must be reviewed.\n"
        )
        reqs = extract_requirements_rule_based(policy_text, "POL-TEST")
        self.assertEqual(len(reqs), 4)

        # Check all are initial Candidates
        for r in reqs:
            self.assertEqual(r.status, "Candidate")

        req_texts = [r.text for r in reqs]
        self.assertTrue(any("multi-factor" in t for t in req_texts))
        self.assertTrue(any("90 days" in t for t in req_texts))
        self.assertTrue(any("24 hours" in t for t in req_texts))
        self.assertTrue(any("45 days" in t for t in req_texts))

    def test_requirement_approval_and_storage(self):
        """Test requirement status progression and human approval."""
        req = Requirement(
            requirement_id="REQ-001",
            policy_id="POL-001",
            text="Privileged accounts must use MFA.",
            source_snippet="Privileged accounts must use MFA.",
            category="Access Control",
            metric="MFA %",
            threshold="100%",
            data_source="accounts.csv",
            status="Candidate"
        )
        self.storage.save_requirements([req])
        fetched = self.storage.get_requirement("REQ-001")
        self.assertEqual(fetched.status, "Candidate")

        # Human approves
        updated = self.storage.update_requirement("REQ-001", {"status": "Approved"})
        self.assertEqual(updated.status, "Approved")

    def test_control_mapping(self):
        """Test framework mapping to NIST, ISO 27001, and CIS."""
        req_mfa = Requirement(
            requirement_id="REQ-001",
            policy_id="POL-001",
            text="Privileged accounts must use multi-factor authentication.",
            source_snippet="All admin accounts require MFA.",
            category="Access Control",
            metric="MFA compliance percentage",
            threshold="100%",
            data_source="accounts.csv",
            status="Approved"
        )
        mapping = mapping_engine.map_requirement(req_mfa)
        self.assertEqual(mapping.control_id, "R1")
        self.assertIn("NIST IA-2(1)", mapping.nist_mapping)
        self.assertIn("ISO/IEC 27001:2022 A.8.5", mapping.iso_mapping)
        self.assertIn("CIS Control 5.2", mapping.cis_mapping)
        self.assertEqual(mapping.automated_check_id, "R1")
        self.assertEqual(mapping.status, "Candidate")

    def test_compliance_execution_r1_to_r4(self):
        """Test continuous compliance execution for approved R1-R4 controls."""
        mappings = [
            ControlMapping(
                mapping_id="MAP-R1",
                control_id="R1",
                control_name="Admin MFA",
                policy_id="POL-001",
                requirement_id="REQ-001",
                metric="MFA %",
                threshold="100%",
                data_source="accounts.csv",
                automated_check_id="R1",
                status="Approved"
            ),
            ControlMapping(
                mapping_id="MAP-R2",
                control_id="R2",
                control_name="Access Reviews",
                policy_id="POL-001",
                requirement_id="REQ-002",
                metric="Review %",
                threshold="100% in 90 days",
                data_source="accounts.csv",
                automated_check_id="R2",
                status="Approved"
            ),
            ControlMapping(
                mapping_id="MAP-R3",
                control_id="R3",
                control_name="Leaver Removal",
                policy_id="POL-001",
                requirement_id="REQ-003",
                metric="Leaver %",
                threshold="100% in 24 hours",
                data_source="accounts.csv",
                automated_check_id="R3",
                status="Approved"
            ),
            ControlMapping(
                mapping_id="MAP-R4",
                control_id="R4",
                control_name="Dormant Accounts",
                policy_id="POL-001",
                requirement_id="REQ-004",
                metric="Dormant %",
                threshold="No login > 45 days",
                data_source="accounts.csv",
                automated_check_id="R4",
                status="Approved"
            )
        ]

        summary, findings, evidence = execute_compliance(approved_mappings=mappings)

        self.assertEqual(summary["controls_evaluated"], 4)
        self.assertGreater(len(findings), 0)
        self.assertEqual(len(evidence), 4)

        # Confirm results contain R1-R4
        eval_ids = [r["id"] for r in summary["results"]]
        self.assertEqual(eval_ids, ["R1", "R2", "R3", "R4"])

        # Check compliance calculations
        for r in summary["results"]:
            self.assertIn("compliance_pct", r)
            self.assertIn(r["status"], ["GREEN", "AMBER", "RED"])

    def test_audit_logging(self):
        """Test audit trail recording."""
        entry = self.storage.log_audit("Requirement approved", "REQ-001", "Success")
        logs = self.storage.list_audit_logs()
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0].action, "Requirement approved")


if __name__ == "__main__":
    unittest.main()
