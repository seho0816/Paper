import os


def validate_workspace_path(
    raw_path: str,
) -> str:
    if not raw_path.startswith(
        "workspace/"
    ):
        raise ValueError(
            "invalid workspace path"
        )

    return os.path.normpath(
        raw_path
    )
