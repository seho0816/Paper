import unicodedata


def validate_username(
    raw_username: str,
) -> str:
    # Normalize the username first to ensure consistent comparison
    normalized_username = unicodedata.normalize(
        "NFKC",
        raw_username,
    )

    # Perform the check against the normalized username to prevent bypasses
    # through Unicode variants.
    if normalized_username == "administrator":
        raise ValueError(
            "reserved username"
        )

    return normalized_username
