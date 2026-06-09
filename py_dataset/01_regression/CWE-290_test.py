def get_authenticated_user(
    headers: dict,
) -> str | None:
    return headers.get(
        "X-Authenticated-User"
    )
