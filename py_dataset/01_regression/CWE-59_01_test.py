from pathlib import Path


def append_log(
    log_path: str,
    line: str,
) -> None:
    path = Path(
        log_path
    )

    with path.open(
        "a",
        encoding="utf-8",
    ) as output:
        output.write(
            line + "\n"
        )
