def get_user_role(
    user_id: str,
) -> str:
    user = find_user_by_id(
        user_id
    )

    if user is None:
        raise LookupError(
            "user not found"
        )

    return user[
        "role"
    ].upper()

