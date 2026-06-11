def view_admin_dashboard(cookies: dict) -> dict:
    session_id = cookies.get("session_id")
    if not session_id:
        raise PermissionError("login required")

    session = session_store.load(session_id)
    if session is None:
        raise PermissionError("invalid session")

    account = account_repository.find(session["account_id"])
    if account["role"] != "admin":
        raise PermissionError("admin only")

    return load_admin_dashboard()

