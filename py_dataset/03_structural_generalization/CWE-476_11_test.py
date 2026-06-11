import sys


users = {
    "user-100": {
        "role": "member"
    }
}


def find_user(user_id: str) -> dict | None:
    return users.get(user_id)


class UserSummaryService:
    def role_label(self, user_id: str) -> str:
        account = find_user(user_id)
        return account["role"].upper()


def read_user_id() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "missing-user"


def main() -> None:
    service = UserSummaryService()
    print(service.role_label(read_user_id()))


if __name__ == "__main__":
    main()
