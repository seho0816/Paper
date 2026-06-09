def get_role_from_cookie(cookies: dict) -> str:
    return cookies.get("role", "guest")


def view_admin_dashboard(cookies: dict) -> dict:
    role = get_role_from_cookie(cookies)
    if role != "admin":
        raise PermissionError("admin only")
    return load_admin_dashboard()
