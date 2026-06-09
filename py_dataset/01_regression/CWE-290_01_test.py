def is_administrator(
    headers: dict,
) -> bool:
    return (
        headers.get(
            "X-Admin"
        )
        == "true"
    )
