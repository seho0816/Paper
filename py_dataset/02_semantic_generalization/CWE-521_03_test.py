def register_account(
    username: str,
    password: str,
) -> None:
    if len(
        password
    ) < 6:
        raise ValueError(
            "password too short"
        )

    create_account(
        username,
        password,
    )
