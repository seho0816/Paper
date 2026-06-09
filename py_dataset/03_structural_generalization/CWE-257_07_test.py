class RecoverablePasswordStore:
    def load_plaintext(
        self,
        account_id: str,
    ) -> str:
        encrypted = database.load_password_blob(
            account_id
        )

        return password_cipher.decrypt(
            encrypted
        ).decode(
            "utf-8"
        )


class AuthenticationService:
    def __init__(
        self,
        store: RecoverablePasswordStore,
    ) -> None:
        self._store = store

    def authenticate(
        self,
        account_id: str,
        submitted_password: str,
    ) -> bool:
        return (
            self._store.load_plaintext(
                account_id
            )
            == submitted_password
        )
