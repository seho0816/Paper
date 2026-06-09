import hashlib

import requests


def download_verified_code(
    update_url: str,
    expected_sha256: str,
) -> bytes:
    response = requests.get(
        update_url,
        timeout=10,
    )
    response.raise_for_status()
    code = response.content
    actual_sha256 = hashlib.sha256(
        code
    ).hexdigest()

    if not secrets_compare(
        actual_sha256,
        expected_sha256,
    ):
        raise PermissionError(
            "update integrity check failed"
        )

    return code


def secrets_compare(
    left: str,
    right: str,
) -> bool:
    import hmac

    return hmac.compare_digest(
        left,
        right,
    )

