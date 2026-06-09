def sanitize_export_path(
    path_value: str,
) -> str:
    return path_value.replace(
        "/etc/",
        "",
    )
