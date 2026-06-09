from pathlib import Path


def resolve_user_path(
    raw_path: str,
) -> Path:
    if raw_path.startswith(
        "/"
    ):
        raise ValueError(
            "absolute path denied"
        )

    return Path(
        raw_path
    ).expanduser()
