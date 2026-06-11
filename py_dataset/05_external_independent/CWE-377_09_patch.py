from pathlib import Path
import tempfile
import os
import re

def create_archive(
    user_id: str,
    content: bytes,
) -> Path:
    safe_user_id = re.sub(r'[^\w-]', '_', user_id)
    prefix = f"archive-{safe_user_id}-"
    
    # dir="/tmp" 제거
    fd, path_str = tempfile.mkstemp(suffix=".zip", prefix=prefix)
    
    path = Path(path_str)

    with os.fdopen(fd, 'wb') as f:
        f.write(content)

    return path