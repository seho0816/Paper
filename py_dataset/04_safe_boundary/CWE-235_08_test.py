from urllib.parse import parse_qs


SECURITY_PARAMETERS = {
    "amount",
    "account_id",
    "role",
}


def parse_request(
    query_string: str,
) -> dict[str, str]:
    values = parse_qs(
        query_string,
        keep_blank_values=True,
    )

    for name in SECURITY_PARAMETERS:
        if len(
            values.get(
                name,
                [],
            )
        ) > 1:
            raise ValueError(
                f"duplicate parameter: {name}"
            )

    return {
        name: items[0]
        for name, items in values.items()
        if items
    }
