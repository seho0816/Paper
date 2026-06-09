def register_account(
    email: str,
    password: str,
) -> tuple[dict, int]:
    if find_user_by_email(
        email
    ) is not None:
        return {
            "error": "email already registered",
        }, 409

    create_account(
        email,
        password,
    )

    return {
        "created": True,
    }, 201
