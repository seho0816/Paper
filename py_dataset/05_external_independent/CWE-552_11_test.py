from pathlib import Path


STATIC_ROOT = Path("static")


async def create_secret_export(account_id: str, content: bytes) -> dict:
    target = STATIC_ROOT / "exports" / f"{account_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return {
        "url": "/static/exports/" + target.name,
    }
