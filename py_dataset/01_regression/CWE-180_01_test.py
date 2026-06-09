import unicodedata


def validate_username(
    raw_username: str,
) -> str:
    if raw_username == "administrator":
        raise ValueError(
            "reserved username"
        )

    return unicodedata.normalize(
        "NFKC",
        raw_username,
    )
