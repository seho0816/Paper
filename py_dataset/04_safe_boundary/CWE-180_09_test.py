import unicodedata


RESERVED_NAMES = {
    "administrator",
    "root",
    "system",
}


def validate_username(
    raw_username: str,
) -> str:
    normalized = unicodedata.normalize(
        "NFKC",
        raw_username,
    )

    if normalized.casefold() in {
        name.casefold()
        for name in RESERVED_NAMES
    }:
        raise ValueError(
            "reserved username"
        )

    return normalized
