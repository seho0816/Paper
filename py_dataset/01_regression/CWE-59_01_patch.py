from pathlib import Path


def append_log(
    log_path: str,
    line: str,
) -> None:
    path = Path(
        log_path
    )

    if path.is_symlink():
        raise ValueError(f"Cannot append to a symbolic link: {log_path}")

    with path.open(
        "a",
        encoding="utf-8",
    ) as output:
        output.write(
            line + "\n"
        )
