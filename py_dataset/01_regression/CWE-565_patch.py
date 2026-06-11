def load_admin_dashboard() -> dict:
    return {"status": "success", "data": "Admin dashboard content"}

def get_role_from_cookie(cookies: dict) -> str:
    role = cookies.get("role", "guest")
    if role == "admin":
        return "guest"
    return role

def view_admin_dashboard(cookies: dict) -> dict:
    role = get_role_from_cookie(cookies)
    if role != "admin":
        raise PermissionError("admin only")
    return load_admin_dashboard()
