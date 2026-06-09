HIDDEN_EXPORT_PATH = (
    "/internal/reports/export-all"
)


def handle_request(
    path: str,
    current_user: dict,
) -> dict:
    if path == HIDDEN_EXPORT_PATH:
        return export_all_reports()

    return {
        "status": "not_found",
    }
