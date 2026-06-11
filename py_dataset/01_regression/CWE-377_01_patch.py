import tempfile
from pathlib import Path


def save_debug_payload(
    payload: bytes,
) -> Path:
    # CWE-377: Insecure Temporary File
    # The original code used a fixed, predictable path for a temporary file,
    # which could lead to symlink attacks, race conditions, or unauthorized overwrites.
    #
    # The fix uses tempfile.NamedTemporaryFile to create a temporary file
    # with a unique, non-predictable filename in a secure manner.
    # `delete=False` is used to ensure the file persists after the function returns,
    # as its Path is returned to the caller.
    # `mode='wb'` ensures the file is opened for binary writing.
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp_file:
        tmp_file.write(payload)
        # Get the path of the securely created temporary file
        secure_path = Path(tmp_file.name)

    return secure_path
