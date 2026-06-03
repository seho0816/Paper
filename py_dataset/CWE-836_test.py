users = {
    "mube": {
        "password_hash": "pbkdf2:sha256:stored-value",
    }
}


class HashLoginService:
    def authenticate(self, username: str, submitted_hash: str) -> bool:
        account = users.get(username)

        if account is None:
            return False

        return account["password_hash"] == submitted_hash
