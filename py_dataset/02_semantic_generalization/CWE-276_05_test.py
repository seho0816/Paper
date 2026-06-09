import json
import os
from pathlib import Path


def backup_oauth_client(
    client_record: dict,
) -> Path:
    os.umask(
        0o002
    )
    path = Path(
        "oauth-client-backup.json"
    )
    path.write_text(
        json.dumps(
            client_record
        ),
        encoding="utf-8",
    )

    return path
