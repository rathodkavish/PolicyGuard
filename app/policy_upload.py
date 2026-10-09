"""Policy upload handler: safely validates, saves, extracts text, and registers policy."""
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, Any

from app.models import Policy
from app.policy_parser import validate_file, extract_text_from_file, detect_metadata
from app.storage import db

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def handle_policy_upload(filename: str, file_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Safely handles uploaded policy documents without executing them.
    Returns: (success: bool, message: str, data: dict)
    """
    # 1. Validation
    is_valid, err_msg = validate_file(filename, len(file_bytes))
    if not is_valid:
        return False, err_msg, {}

    # 2. Safe file storage with generated unique ID
    policy_num = len(db.list_policies()) + 1
    policy_id = f"POL-{policy_num:03d}"
    clean_stem = "".join(c for c in Path(filename).stem if c.isalnum() or c in ("-", "_"))[:30]
    safe_filename = f"{policy_id}_{clean_stem}{Path(filename).suffix.lower()}"
    saved_path = UPLOAD_DIR / safe_filename

    try:
        saved_path.write_bytes(file_bytes)
    except Exception as e:
        return False, f"Failed to save uploaded file: {str(e)}", {}

    # 3. Safe text extraction
    try:
        extracted_text = extract_text_from_file(saved_path)
    except Exception as e:
        return False, f"Text extraction failed: {str(e)}", {}

    if not extracted_text.strip():
        return False, "Uploaded document contains no readable text or could not be parsed.", {}

    # 4. Metadata detection
    meta = detect_metadata(extracted_text, filename)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    policy = Policy(
        policy_id=policy_id,
        name=meta["name"],
        filename=filename,
        category=meta["category"],
        version=meta["version"],
        owner=meta["owner"],
        effective_date=meta["effective_date"],
        review_date=meta["review_date"],
        uploaded_at=now_str,
        status="Draft",
        file_path=str(saved_path),
        raw_text=extracted_text,
        word_count=meta["word_count"],
        extraction_status="Success"
    )

    db.save_policy(policy)

    return True, "Policy uploaded and analyzed successfully.", policy.dict()
