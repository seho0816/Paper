import json
import os
from pathlib import Path


APPLICATION_SHARED = Path('/opt/application/shared')


def persist_signing_key_record(
    key_record: dict,
) -> Path:
    destination = APPLICATION_SHARED / 'signing-key.json'

    # CWE-277: Insecure Inherited Permissions
    # The original Path.write_text() method creates files with permissions
    # dictated by the process's umask, which can be insecure (e.g., world-readable).
    # To fix this, we explicitly set secure permissions after writing the file,
    # ensuring only the owner has read/write access (0o600).
    
    # Write the content to the file
    with open(destination, 'w', encoding='utf-8') as f:
        f.write(json.dumps(key_record))
    
    # Set secure permissions: owner read/write, no access for group or others
    os.chmod(destination, 0o600)
    
    return destination
