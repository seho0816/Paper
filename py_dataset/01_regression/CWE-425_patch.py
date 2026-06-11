HIDDEN_EXPORT_PATH = (
    "/internal/reports/export-all"
)


def handle_request(
    path: str,
    current_user: dict,
) -> dict:
    if path == HIDDEN_EXPORT_PATH:
        # CWE-425 fix: Implement proper authorization to prevent forced browsing.
        # Only users with the 'admin' role should be able to access this hidden path.
        # Assuming 'current_user' dictionary contains a 'roles' key with a list of strings.
        user_roles = current_user.get("roles", [])
        if "admin" in user_roles:
            return export_all_reports()
        else:
            # Return an unauthorized status if the user lacks the necessary permissions.
            return {
                "status": "unauthorized",
                "message": "Access to this resource requires administrator privileges.",
            }

    return {
        "status": "not_found",
    }
