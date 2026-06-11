import os


def save_report_if_absent(
    report_path: str,
    content: str,
) -> None:
    with open(
        report_path,
        "x",  # Use 'x' mode for exclusive creation to prevent CWE-367 (TOCTOU).
        # If the file exists, FileExistsError will be raised, matching the original logic.
        encoding="utf-8",
    ) as output:
        output.write(content)
