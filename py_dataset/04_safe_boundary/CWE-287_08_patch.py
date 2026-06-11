import hmac
import os

from fastapi import Header, HTTPException


def load_active_api_key() -> str:
    """
    Securely loads the active API key. This function's implementation
    addresses CWE-287 by ensuring the API key is retrieved from a secure source
    like environment variables, rather than being hardcoded or stored insecurely.
    """
    api_key = os.environ.get("SECURE_API_KEY")
    if not api_key:
        # In a production environment, this should be a critical configuration error.
        # The application cannot function securely without a properly configured API key.
        raise RuntimeError("SECURE_API_KEY environment variable not set. Application cannot function securely.")
    return api_key


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
