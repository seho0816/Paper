reset_tokens = {
    "RESET-100": {
        "valid": True,
    }
}


class PasswordResetService:
    def reset_password(self, token: str, user_id: str, new_hash: str) -> bool:
        token_record = reset_tokens.get(token)

        if token_record is None or not token_record["valid"]:
            return False

        update_password_hash(user_id, new_hash)
        return True


def update_password_hash(user_id: str, new_hash: str) -> None:
    print(user_id, new_hash)
