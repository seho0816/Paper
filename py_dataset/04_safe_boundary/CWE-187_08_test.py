import hmac


def verify_service_api_key(
    provided_key: str,
    stored_key: str,
) -> bool:
    return hmac.compare_digest(
        provided_key,
        stored_key,
    )
