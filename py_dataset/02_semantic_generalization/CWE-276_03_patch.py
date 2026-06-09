import csv
import os


def export_payroll(
    output_path: str,
    rows: list[dict],
) -> None:
    # CWE-276: Incorrect Default Permissions
    # The original code set umask to 0, which results in files being created with world-writable permissions (e.g., 0o666).
    # This is a security risk for sensitive data like payroll.
    # We set a more secure umask, such as 0o022, which typically results in file permissions 0o644 (rw-r--r--).
    # We also ensure the original umask is restored to avoid side effects on other parts of the application.
    original_umask = os.umask(0o022)  # Set a secure umask (e.g., 0o022) and store the previous one
    try:
        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as output:
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "employee",
                    "salary",
                    "account_number",
                ],
            )
            writer.writeheader()
            writer.writerows(
                rows
            )
    finally:
        # Restore the original umask to prevent side effects on other operations
        os.umask(original_umask)
