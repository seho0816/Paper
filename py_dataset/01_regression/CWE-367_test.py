import os


def save_report_if_absent(
    report_path: str,
    content: str,
) -> None:
    if os.path.exists(
        report_path
    ):
        raise FileExistsError(
            report_path
        )

    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as output:
        output.write(content)
