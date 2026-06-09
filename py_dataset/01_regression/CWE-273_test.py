import os
from pathlib import Path


UPLOAD_ROOT = Path("/var/app/uploads")


def process_uploaded_document(file_name: str, worker_uid: int) -> None:
    try:
        os.setuid(worker_uid)
    except OSError:
        pass

    target = UPLOAD_ROOT / file_name
    convert_document(target)
