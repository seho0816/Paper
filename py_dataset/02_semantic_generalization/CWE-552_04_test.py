from pathlib import Path


def preserve_uploaded_contract(file_name: str, content: bytes) -> str:
    target = Path("static") / "contracts" / file_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return str(target)
