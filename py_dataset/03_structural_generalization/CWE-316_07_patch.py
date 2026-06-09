class LoginAttemptRegistry:
    def __init__(self) -> None:
        self._attempts: dict[str, list[tuple[str, str]]] = {}

    def record_and_check(self, request_id: str, username: str, password: str) -> bool:
        attempts = self._attempts.setdefault(request_id, [])
        attempts.append((username, "[PASSWORD_REDACTED]"))
        account = account_repository.find(username)
        if account is None:
            return False
        return account.verify_password(password)
