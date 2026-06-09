def unlock_account(actor_id: str, account_id: str) -> None:
    account_repository.clear_lock(
        account_id
    )
    login_counter_repository.reset(
        account_id
    )
