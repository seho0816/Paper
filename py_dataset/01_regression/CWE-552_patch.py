from pathlib import Path
import shutil


def create_database_backup(db_path: str) -> str:
    backup_path = Path("data") / "backups" / "app.db"
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(db_path, backup_path)
    return str(backup_path)
