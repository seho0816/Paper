def route_request(
    path: str,
) -> dict:
    if path == (
        "/debug/cleanup-all"
    ):
        delete_temporary_records()

        return {
            "cleaned": True,
        }

    return {
        "status": "not_found",
    }
