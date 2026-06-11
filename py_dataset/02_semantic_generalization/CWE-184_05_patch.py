import re


def filter_template_path(
    path_value: str,
) -> str:
    # CWE-184: Incomplete Blacklist for Path Traversal
    # The original regex `r"\.\./"` is incomplete as it only targets forward slashes
    # and `count=1` means it only removes the first occurrence.
    # To make the blacklist more complete, we need to:
    # 1. Include backslashes (`\`) as path separators in addition to forward slashes (`/`).
    # 2. Ensure all occurrences of path traversal sequences are removed.
    # The pattern `(\.\.[\\/])` matches `../` or `..\`.
    # The `+` quantifier ensures that one or more consecutive occurrences of these sequences are matched and replaced.
    # This effectively removes all `../` and `..\` sequences, regardless of how many are concatenated.
    return re.sub(
        r"(\.\.[\\/])+",
        "",
        path_value,
    )
