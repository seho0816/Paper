def sanitize_download_name(
    filename: str,
) -> str:
    return filename.replace(
        "../",
        "",
    )
