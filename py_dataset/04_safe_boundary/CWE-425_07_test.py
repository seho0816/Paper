HIDDEN_EXPORT_PATH = (
    "/internal/reports/export-all"
)


def handle_request(
    path: str,
    current_user: dict,
) -> dict:
    if path == HIDDEN_EXPORT_PATH:
        if current_user.get(
            "role"
        ) != "admin":
            raise PermissionError(
                "administrator required"
            )

        return export_all_reports()

    return {
        "status": "not_found",
    }
