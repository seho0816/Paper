def load_account(
    raw_account_id: str,
) -> dict:
    account_id = int(
        float(
            raw_account_id
        )
    )

    return account_repository.find(
        account_id,
    )
