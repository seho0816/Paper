from typing import Any


def load_admin_dashboard() -> dict[str, Any]:
    return {
        "total_users": 100,
        "revenue": 500000,
    }


def get_role_from_cookie(cookies: dict[str, str]) -> str:
    return cookies.get("role", "guest")


def view_admin_dashboard(cookies: dict[str, str]) -> dict[str, Any]:
    role = get_role_from_cookie(cookies)

    if role != "admin":
        raise PermissionError("admin only")

    return load_admin_dashboard()


def main():
    manipulated_cookies = {
        "role": "admin",
    }

    print(view_admin_dashboard(manipulated_cookies))


if __name__ == "__main__":
    main()
