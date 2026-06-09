import os
import tempfile


def create_payroll_report(
    content: str,
) -> str:
    descriptor, path = tempfile.mkstemp(
        prefix="payroll_",
        suffix=".csv",
    )
    os.fchmod(
        descriptor,
        0o600,
    )

    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
    ) as output:
        output.write(
            content
        )

    return path
