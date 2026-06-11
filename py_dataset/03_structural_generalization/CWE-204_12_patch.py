import sys


users = {
    "owner@example.com": {
        "password_hash": "hashed-secret"
    }
}


def find_user_by_email(email: str) -> dict | None:
    return users.get(email)


def verify_password(password: str, password_hash: str) -> bool:
    return password == "correct-password" and password_hash == "hashed-secret"


class LoginController:
    def authenticate(self, email: str, password: str) -> dict[str, object]:
        account = find_user_by_email(email)

        # CWE-204: Observable Discrepancy fix
        # Return a generic error message regardless of whether the email
        # is unknown or the password mismatches, to prevent enumeration.
        if account is None:
            return {
                "ok": False,
                "reason": "authentication failed",
            }

        if not verify_password(password, account["password_hash"]):
            return {
                "ok": False,
                "reason": "authentication failed",
            }

        return {
            "ok": True,
            "reason": "authenticated",
        }


def read_login() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]

    return "notfound@example.com", "guess"


def main() -> None:
    email, password = read_login()
    controller = LoginController()
    print(controller.authenticate(email, password))


if __name__ == "__main__":
    main()
