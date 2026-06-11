from pathlib import Path


STATIC_ROOT = Path("static")


async def create_secret_export(account_id: str, content: bytes) -> dict:
    # CWE-552 remediation: Sanitize account_id to prevent path traversal.
    # Path(account_id).name extracts only the base filename component,
    # stripping any directory parts (e.g., '..' or '/').
    sanitized_account_id = Path(account_id).name
    target = STATIC_ROOT / "exports" / f"{sanitized_account_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return {
        "url": "/static/exports/" + target.name,
    }
