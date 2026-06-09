from pathlib import Path


BACKUP_ROOT = Path(
    "/var/backups/application"
)


def list_backups() -> list[dict]:
    return [
        {
            "name": path.name,
            "absolute_path": str(
                path.resolve()
            ),
            "size": path.stat().st_size,
        }
        for path in BACKUP_ROOT.iterdir()
    ]
