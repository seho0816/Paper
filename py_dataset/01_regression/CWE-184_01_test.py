def sanitize_windows_name(
    filename: str,
) -> str:
    return filename.replace(
        "..\\",
        "",
    )
