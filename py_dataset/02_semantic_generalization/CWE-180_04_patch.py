import os


def validate_workspace_path(
    raw_path: str,
) -> str:
    # Normalize the path first to resolve any '..' components and redundant separators.
    # This ensures that any attempts to traverse out of the intended directory
    # using path components like '..' are resolved before the security check.
    normalized_path = os.path.normpath(raw_path)

    # After normalization, verify that the path still strictly starts with "workspace/".
    # This prevents an attacker from using "workspace/../sensitive_file.txt"
    # which would pass the original startswith check but normalize to "sensitive_file.txt",
    # escaping the intended workspace.
    if not normalized_path.startswith(
        "workspace/"
    ):
        raise ValueError(
            "invalid workspace path"
        )

    return normalized_path
