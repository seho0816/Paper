def verify_api_key(
    submitted_key: str,
    stored_key: str,
) -> bool:
    return (
        submitted_key.upper()
        == stored_key.upper()
    )
