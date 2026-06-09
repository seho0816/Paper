from pathlib import Path


def save_customer_export(account_id: str, content: bytes) -> str:
    target = Path("wwwroot") / "exports" / f"customer-{account_id}.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return "/exports/" + target.name
