class LegacyAccountController:
    def update_password(
        self,
        current_user: dict,
        new_password_hash: str,
    ) -> dict:
        account_repository.set_password(
            current_user["id"],
            new_password_hash,
        )

        return {
            "updated": True,
        }
