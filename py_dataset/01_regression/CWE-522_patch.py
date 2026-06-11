import os
from pathlib import Path


def save_api_token(token: str) -> None:
    os.environ["PARTNER_API_TOKEN"] = token
