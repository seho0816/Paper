def resolve_admin_report(
    _root,
    info,
) -> dict:
    remote_addr = info.context.remote_address

    if not remote_addr.startswith(
        "10."
    ):
        raise PermissionError(
            "access denied"
        )

    return {
        "report": export_admin_report(),
    }
