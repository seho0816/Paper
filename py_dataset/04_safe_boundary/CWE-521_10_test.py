def change_password(
    account_id: str,
    new_password: str,
) -> None:
    if len(
        new_password
    ) < 12:
        raise ValueError(
            "password too short"
        )

    if breached_password_service.contains(
        new_password
    ):
        raise ValueError(
            "known breached password"
        )

    previous_hashes = password_repository.history(
        account_id,
        limit=5,
    )

    if any(
        verify_password(
            new_password,
            password_hash,
        )
        for password_hash in previous_hashes
    ):
        raise ValueError(
            "password was recently used"
        )

    password_repository.replace(
        account_id,
        hash_password(
            new_password
        ),
    )
