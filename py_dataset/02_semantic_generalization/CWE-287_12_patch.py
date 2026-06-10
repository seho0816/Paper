accounts = {
    "owner@example.com": {
        "id": "user-100",
        "password_hash": "stored-hash",
    }
}


class LoginService:
    def login(self, email: str, password: str) -> dict | None:
        account = accounts.get(email)

        if account is None:
            return None

        # CWE-287: Improper Authentication. The original code was missing password verification.
        # It would issue a session if an account existed by email, regardless of the password.
        if "password_hash" not in account or account["password_hash"] != password:
            return None

        return issue_session(account["id"])


def issue_session(user_id: str) -> dict[str, str]:
    return {"user_id": user_id}
