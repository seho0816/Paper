failed_attempts: dict[str, int] = {}


class AccountLockoutService:
    def record_failure(self, username: str) -> None:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1

        if failed_attempts[username] >= 1:
            disable_account(username)


def disable_account(username: str) -> None:
    print(username)
