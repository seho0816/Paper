import os
from pathlib import Path


UPLOAD_ROOT = Path("/var/app/uploads")


def process_uploaded_document(file_name: str, worker_uid: int) -> None:
    # CWE-273 fix:
    # The original code ignored potential OSErrors during privilege dropping (os.setuid),
    # which would allow subsequent operations to proceed with higher, unintended privileges.
    # By removing the 'try...except OSError: pass' block, any failure to
    # drop privileges will raise an OSError and halt execution,
    # preventing privileged operations from being performed as the wrong user.
    os.setuid(worker_uid)

    target = UPLOAD_ROOT / file_name
    # Assuming convert_document is an existing function defined elsewhere.
    # Its implementation is not part of the required fix.
    convert_document(target)
