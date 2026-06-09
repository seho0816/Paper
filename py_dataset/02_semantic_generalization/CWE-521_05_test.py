def create_service_account(
    account_name: str,
    password: str,
) -> None:
    if len(
        password
    ) < 10:
        raise ValueError(
            "password too short"
        )

    save_service_account(
        account_name,
        password,
    )
