import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from app.main import app

def test_all_sample_pdfs():
    client = TestClient(app)
    pdf_files = [
        "sample_access_control_policy.pdf",
        "sample_authentication_policy.pdf",
        "sample_data_protection_policy.pdf",
        "sample_logging_monitoring_policy.pdf"
    ]

    for fname in pdf_files:
        p = Path("sample_data") / fname
        assert p.exists(), f"File {p} does not exist"
        with open(p, "rb") as f:
            res = client.post("/api/policies/upload", files={"file": (fname, f, "application/pdf")})
        assert res.status_code == 200, res.text
        pol = res.json()["policy"]
        pid = pol["policy_id"]
        print(f"File: {fname}")
        print(f"  ID: {pid}")
        print(f"  Name: {pol['name']}")
        print(f"  Category: {pol['category']}")
        print(f"  Version: {pol['version']}")
        print(f"  Owner: {pol['owner']}")
        print(f"  Effective: {pol['effective_date']}")
        print(f"  Review: {pol['review_date']}")

        # Extraction
        r_res = client.post(f"/api/policies/{pid}/extract-requirements")
        assert r_res.status_code == 200
        reqs = r_res.json()["requirements"]
        print(f"  Candidate Requirements ({len(reqs)}):")
        for r in reqs:
            print(f"    - [{r['requirement_id']}] {r['text']} (Confidence: {r['confidence']})")
        print("-" * 60)

if __name__ == "__main__":
    test_all_sample_pdfs()
