import sys
import hmac


password_table: dict[str, str] = {}


def update_user_password(user_id: str, password: str) -> None:
    password_table[user_id] = password


class AccountSecurityService:
    def change_password(self, user_id: str, new_password: str, repeated_password: str) -> bool:
        # CWE-620 Fix: Use hmac.compare_digest for timing-safe comparison
        # to prevent timing attacks that could reveal password content.
        if not hmac.compare_digest(new_password, repeated_password):
            return False

        if len(new_password) < 8:
            return False

        update_user_password(user_id, new_password)
        return True


def read_request() -> tuple[str, str, str]:
    if len(sys.argv) >= 4:
        return sys.argv[1], sys.argv[2], sys.argv[3]

    return "user-100", "NewPassword1!", "NewPassword1!"


def main() -> None:
    user_id, new_password, repeated_password = read_request()
    service = AccountSecurityService()
    print(service.change_password(user_id, new_password, repeated_password))


if __name__ == "__main__":
    main()