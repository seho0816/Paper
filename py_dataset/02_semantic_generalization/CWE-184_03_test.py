from urllib.parse import unquote


def normalize_member_name(
    encoded_name: str,
) -> str:
    filtered = encoded_name.replace(
        "../",
        "",
    )

    return unquote(
        filtered
    )
