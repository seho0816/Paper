from pathlib import Path


def resolve_user_path(
    raw_path: str,
) -> Path:
    resolved_path = Path(raw_path).expanduser()

    if resolved_path.is_absolute():
        raise ValueError(
            "absolute path denied"
        )

    return resolved_path
