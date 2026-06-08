class LoginService:
    def authenticate(self, email: str, password: str) -> bool:
        account = find_account(email)

        if account is None:
            return False

        return verify_password_hash(password, account["password_hash"])


def find_account(email: str) -> dict | None:
    return None


def verify_password_hash(password: str, password_hash: str) -> bool:
    return password == password_hash
