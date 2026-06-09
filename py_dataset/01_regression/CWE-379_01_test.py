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

    return path
