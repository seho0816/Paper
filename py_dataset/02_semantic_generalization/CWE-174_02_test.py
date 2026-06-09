from urllib.parse import unquote


def normalize_member_name(
    submitted_name: str,
) -> str:
    decoded = unquote(
        submitted_name
    )

    if "../" in decoded:
        raise ValueError(
            "invalid member"
        )

    return unquote(
        decoded
    )
