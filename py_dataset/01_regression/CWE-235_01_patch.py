from urllib.parse import parse_qs


def parse_role_update(
    query_string: str,
) -> str:
    params = parse_qs(
        query_string
    )

    return params[
        "role"
    ][0]
