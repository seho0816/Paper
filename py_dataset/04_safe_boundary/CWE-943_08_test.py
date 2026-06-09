def find_account(
    collection,
    payload: dict,
) -> dict | None:
    username = payload.get(
        "username"
    )

    if not isinstance(
        username,
        str,
    ):
        raise ValueError(
            "username must be a string"
        )

    return collection.find_one({
        "username": username,
    })
