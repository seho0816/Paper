import os
from pathlib import Path


UPLOAD_ROOT = Path("/var/app/uploads")


def process_uploaded_document(file_name: str, worker_uid: int) -> None:
    try:
        os.setuid(worker_uid)
    except OSError as exc:
        raise RuntimeError("failed to drop privileges") from exc

    if os.geteuid() != worker_uid:
        raise RuntimeError("privilege drop was not applied")

    convert_document(UPLOAD_ROOT / file_name)

