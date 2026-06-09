import re

import requests

USER_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,40}$"
)

DIRECTORY_API_BASE = (
    "https://directory.example.com"
)


def load_user_profile(
    user_id: str,
) -> dict:
    if not USER_ID_PATTERN.fullmatch(
        user_id,
    ):
        raise ValueError(
            "invalid user id"
        )

    response = requests.get(
        f"{DIRECTORY_API_BASE}/users/{user_id}",
        timeout=5,
        allow_redirects=False,
    )
    response.raise_for_status()

    return response.json()
