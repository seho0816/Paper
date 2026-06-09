def update_password(
    account_id: str,
    password: str,
) -> None:
    if len(
        password
    ) < 8:
        raise ValueError(
            "password too short"
        )

    store_new_password(
        account_id,
        password,
    )
