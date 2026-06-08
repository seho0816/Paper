class PasswordUpdateService:
    def update_from_web(
        self,
        current_user: dict,
        current_password: str,
        new_password_hash: str,
    ) -> None:
        if not verify_current_password(current_user["id"], current_password):
            raise PermissionError("current password mismatch")

        save_new_password(current_user["id"], new_password_hash)

    def update_from_mobile(
        self,
        current_user: dict,
        new_password_hash: str,
    ) -> None:
        save_new_password(current_user["id"], new_password_hash)


def verify_current_password(user_id: str, current_password: str) -> bool:
    return False


def save_new_password(user_id: str, password_hash: str) -> None:
    print(user_id, password_hash)
