def inspect_api_key(
    submitted_key: str,
) -> dict:
    record = api_key_store.find(
        submitted_key
    )

    # CWE-204: Observable Response Discrepancy (Information Exposure Through an Error Message)
    # The original code differentiated responses for non-existent keys ("unknown_key")
    # versus existing but revoked keys ("revoked" along with the owner).
    # This allowed an attacker to enumerate valid API keys by distinguishing
    # between non-existent and revoked keys.
    # To mitigate, unify the response for non-existent and revoked keys.
    # Both cases should return a generic state that does not reveal whether
    # the key exists or its revocation status, preventing information leakage.
    if record is None or record["revoked"]:
        return {
            "state": "unknown_key",  # This state now covers both non-existent and revoked keys.
        }

    # If the code reaches here, the record exists and is not revoked, meaning it's active.
    return {
        "state": "active",
        "owner": record["owner"],
    }
