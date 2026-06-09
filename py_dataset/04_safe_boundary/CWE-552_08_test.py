from pathlib import Path
import shutil


BACKUP_ROOT = Path("/var/app/private_backups")


def create_database_backup(db_path: str) -> str:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_path = BACKUP_ROOT / "app.db"
    shutil.copyfile(db_path, backup_path)
    backup_path.chmod(0o600)
    return str(backup_path)
