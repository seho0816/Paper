from typing import Any


deleted_users: list[str] = []


def remove_user(user_id: str) -> None:
    deleted_users.append(user_id)


def can_access_admin(headers: dict[str, str]) -> bool:
    return headers.get("X-Admin") == "true"


def delete_user(user_id: str, headers: dict[str, str]) -> dict[str, Any]:
    if not can_access_admin(headers):
        raise PermissionError("admin only")

    remove_user(user_id)

    return {
        "deleted": user_id,
        "status": "ok",
    }


def main():
    attacker_headers = {
        "X-Admin": "true",
    }

    print(delete_user("victim-user", attacker_headers))


if __name__ == "__main__":
    main()
