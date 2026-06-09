def inspect_api_key(
    submitted_key: str,
) -> dict:
    record = api_key_store.find(
        submitted_key
    )

    if record is None:
        return {
            "state": "unknown_key",
        }

    if record["revoked"]:
        return {
            "state": "revoked",
            "owner": record["owner"],
        }

    return {
        "state": "active",
        "owner": record["owner"],
    }
