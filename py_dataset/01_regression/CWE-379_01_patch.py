from pathlib import Path


SHARED_WORK_DIR = Path(
    "/var/tmp/shared-jobs"
)


def write_job_token(
    token: str,
) -> Path:
    path = (
        SHARED_WORK_DIR
        / "job-token.txt"
    )
    path.write_text(
        token,
        encoding="utf-8",
    )
    # CWE-379 fix: Set restrictive file permissions to prevent unauthorized access.
    # 0o600 grants read and write permissions only to the file owner.
    path.chmod(0o600)

    return path
