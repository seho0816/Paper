def resolve_preview_export(
    _root,
    info,
    report_id: str,
) -> dict:
    report = report_repository.find(
        report_id
    )

    if report is None:
        raise ValueError(f"Report with ID '{report_id}' not found.")

    export_body = build_large_export_archive(
        report
    )

    if info.context.current_user is None:
        raise PermissionError(
            "authentication required"
        )

    return {
        "size": len(
            export_body
        ),
    }
