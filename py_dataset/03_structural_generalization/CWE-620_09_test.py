class Account:
    def __init__(
        self,
        account_id: str,
        password_hash: str,
    ) -> None:
        self.account_id = account_id
        self.password_hash = password_hash

    def change_password(
        self,
        new_password: str,
        confirmation: str,
    ) -> bool:
        if new_password != confirmation:
            return False

        self.password_hash = password_hasher.hash(
            new_password
        )
        return True


def update_account_password(
    session_id: str,
    payload: dict,
) -> bool:
    session = session_repository.require(
        session_id
    )
    account = account_repository.load(
        session.account_id
    )
    changed = account.change_password(
        payload['new_password'],
        payload['confirmation'],
    )

    if changed:
        account_repository.save(account)

    return changed
