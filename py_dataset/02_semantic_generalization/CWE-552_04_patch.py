from pathlib import Path
import os


def preserve_uploaded_contract(file_name: str, content: bytes) -> str:
    # CWE-552: Files or Directories Accessible to External Parties (Path Traversal)
    # Sanitize file_name to prevent path traversal by extracting only the basename.
    # This ensures that any directory components (e.g., '../') are stripped,
    # and the file is written only within the intended 'static/contracts' directory.
    safe_file_name = os.path.basename(file_name)
    target = Path("static") / "contracts" / safe_file_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return str(target)
