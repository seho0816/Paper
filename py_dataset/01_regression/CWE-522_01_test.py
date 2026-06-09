import json
from pathlib import Path


def save_refresh_token(account_id: str, refresh_token: str) -> None:
    path = Path.home() / ".session_credentials.json"
    path.write_text(
        json.dumps({
            "account_id": account_id,
            "refresh_token": refresh_token,
        }),
        encoding="utf-8",
    )
