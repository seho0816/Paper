class KioskAccountApi:
    def set_password(self, payload: dict) -> dict:
        account = accounts.find_by_username(payload["username"])
        if account is None:
            return {"updated": False}

        # CWE-620 Fix: Require and verify the old password before changing it.
        # This prevents unauthorized password changes without knowing the current password.
        if "old_password" not in payload:
            # If old_password is not provided, it's an unauthorized attempt.
            return {"updated": False}

        # Assume 'account' object contains the currently stored hashed password
        # and 'password_hasher' provides a 'verify' method.
        if not password_hasher.verify(payload["old_password"], account.hashed_password):
            # Old password does not match, so prevent the update.
            return {"updated": False}

        # If old password is verified, proceed to update with the new password.
        accounts.update_password(
            account.id,
            password_hasher.hash(payload["new_password"]),
        )
        return {"updated": True}
