from pathlib import Path


def save_customer_export(account_id: str, content: bytes) -> str:
    # Sanitize account_id to prevent directory traversal (CWE-552).
    # Using Path(account_id).name extracts only the last path component,
    # effectively removing any '..', '/', or '\' characters that could lead
    # to writing files outside the intended directory.
    sanitized_account_id = Path(account_id).name
    
    target = Path("wwwroot") / "exports" / f"customer-{sanitized_account_id}.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return "/exports/" + target.name
