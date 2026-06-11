import datetime
from datetime import timezone

SIGNING_KEYS = [
    {
        "kid": "old-key",
        "secret": "old-secret",
        "expires_at": "2023-01-01T00:00:00+00:00",
    },
]

def sign_download_url(
    path: str,
) -> str:
    key = SIGNING_KEYS[0]

    expires_at_str = key["expires_at"]
    expiration_time = datetime.datetime.fromisoformat(expires_at_str)
    current_time = datetime.datetime.now(timezone.utc)

    # CWE-324: 서명 키가 만료되었는지 엄격하게 검증하고, 만료 시 즉시 거부
    if current_time >= expiration_time:
        raise ValueError("Cannot sign URL: Signing key has expired.")

    signature = sign_with_secret(
        path,
        key["secret"],
    )

    return (
        f"{path}?kid={key['kid']}"
        f"&sig={signature}"
    )