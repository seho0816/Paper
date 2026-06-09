def resolve_export_records(
    _root,
    info,
    required_role: str,
) -> list[dict]:
    actor = info.context.authenticated_user

    if actor["role"] != required_role:
        raise PermissionError(
            "denied"
        )

    return export_sensitive_records()
