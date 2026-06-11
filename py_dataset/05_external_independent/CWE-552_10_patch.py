from pathlib import Path
from django.conf import settings


def save_database_dump(content: bytes) -> str:
    # CWE-552 fix: Store sensitive database dumps in a secure, non-web-accessible location.
    # settings.MEDIA_ROOT is typically configured to be served directly by the web server,
    # making files stored there publicly accessible.
    # Instead, we use a subdirectory within settings.BASE_DIR, which is generally outside
    # of the web server's public document root by default, ensuring the backup is not exposed.
    secure_dump_dir = settings.BASE_DIR / "secure_backups"
    target = secure_dump_dir / "database.sql"

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    # The original code returned a URL path based on MEDIA_URL.
    # Since the file is now stored in a non-web-accessible location for security,
    # it cannot be accessed via a public URL (like MEDIA_URL).
    # To maintain the function signature (returning a string) and provide a useful reference
    # to the stored file, the absolute internal path of the securely saved dump is returned.
    # If external access is required, a separate, authenticated mechanism (e.g., a Django view)
    # would be necessary to serve this file, which falls outside the scope of this specific
    # CWE-552 fix and maintaining existing functionality.
    return str(target)
