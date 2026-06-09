from pathlib import Path
from django.conf import settings


def save_database_dump(content: bytes) -> str:
    target = Path(settings.MEDIA_ROOT) / "backups" / "database.sql"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return settings.MEDIA_URL + "backups/database.sql"
