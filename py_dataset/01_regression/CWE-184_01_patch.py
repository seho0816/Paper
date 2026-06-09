def sanitize_windows_name(
    filename: str,
) -> str:
    # Normalize path separators for consistent processing on Windows systems,
    # which accept both '/' and '\'.
    normalized_filename = filename.replace("/", "\\")

    # Repeatedly remove '..\' sequences to prevent path traversal.
    # This addresses the incomplete blacklist by handling recursive patterns
    # like '....\' which would otherwise become '..\' after a single pass.
    previous_filename = ""
    while previous_filename != normalized_filename:
        previous_filename = normalized_filename
        normalized_filename = normalized_filename.replace("..\\", "")

    return normalized_filename
