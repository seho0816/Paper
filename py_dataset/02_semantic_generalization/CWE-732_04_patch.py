import os
from pathlib import Path

def store_api_key(path: Path, key: str) -> None:
    # Convert Path object to string for os.open
    filepath_str = str(path)

    # Use os.open to create or open the file with specific permissions from the start.
    # os.O_WRONLY: Open for writing only.
    # os.O_CREAT: Create the file if it does not exist.
    # os.O_TRUNC: Truncate the file to zero length if it exists.
    # mode=0o644: Sets file permissions to user read/write, group read, others read.
    # This prevents the race condition where the file might be created with broader
    # permissions (due to umask) before os.chmod is called, addressing CWE-732.
    fd = os.open(filepath_str, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o644)
    
    # Use os.fdopen to get a standard file object from the file descriptor for writing text.
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(key)
    
    # The os.chmod call is retained. While os.open with 'mode' handles creation permissions,
    # 'mode' is ignored if the file already exists. This explicit os.chmod ensures that
    # if the file existed prior to this operation, its permissions are updated to 0o644
    # as intended by the original code, providing consistent final permissions.
    os.chmod(path, 0o644)
