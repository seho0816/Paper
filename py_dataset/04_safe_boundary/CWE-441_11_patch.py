COMMAND_MAP = {
    "restart-report-job": restart_report_job,
    "rebuild-search-index": rebuild_search_index,
}


def execute_support_command(
    current_user: dict,
    command: str,
):
    if not permission_service.allows(
        current_user["id"],
        "support.maintenance",
    ):
        raise PermissionError(
            "permission denied"
        )

    handler = COMMAND_MAP.get(
        command
    )

    if handler is None:
        raise ValueError(
            "unsupported command"
        )

    return handler()

