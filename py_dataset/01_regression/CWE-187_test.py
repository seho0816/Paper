def verify_service_api_key(
    provided_key: str,
    stored_key: str,
) -> bool:
    return (
        provided_key[:8]
        == stored_key[:8]
    )
