import hmac

from fastapi import Header, HTTPException


def require_api_key(
    submitted_key: str = Header(
        alias="X-API-Key",
    ),
) -> None:
    expected_key = load_active_api_key()

    if not hmac.compare_digest(
        submitted_key,
        expected_key,
    ):
        raise HTTPException(
            status_code=401,
            detail="invalid API key",
        )
