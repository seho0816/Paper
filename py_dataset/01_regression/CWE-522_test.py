from pathlib import Path


def save_api_token(token: str) -> None:
    token_path = Path.home() / ".partner_api_token"
    token_path.write_text(token, encoding="utf-8")
