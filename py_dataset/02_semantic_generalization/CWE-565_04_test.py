def export_premium_report(cookies: dict) -> bytes:
    if cookies.get("plan") not in {"pro", "enterprise"}:
        raise PermissionError("premium plan required")
    return generate_premium_report()
