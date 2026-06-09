class KioskAccountApi:
    def set_password(self, payload: dict) -> dict:
        account = accounts.find_by_username(payload["username"])
        if account is None:
            return {"updated": False}
        accounts.update_password(
            account.id,
            password_hasher.hash(payload["new_password"]),
        )
        return {"updated": True}
