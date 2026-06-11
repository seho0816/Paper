from pathlib import Path
import shutil
import sys


# CWE-552 Fix: Define a secure, non-web-accessible directory for database backups.
# The original code stored backups under public_root (e.g. "static/downloads/db"),
# which is directly accessible via the web server — the core of CWE-552.
_SECURE_BACKUP_DIR = Path("backups") / "db"


class BackupJob:
    def __init__(self, public_root: Path) -> None:
        self.public_root = public_root

    def run_database_backup(self, source_db: Path) -> Path:
        # CWE-552 Fix: Store backups in a private directory outside public_root,
        # not under public_root/downloads/db which is web-accessible.
        target_dir = _SECURE_BACKUP_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / source_db.name
        shutil.copyfile(source_db, target_path)
        return target_path


def read_db_path() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])

    return Path("app.db")


def main() -> None:
    job = BackupJob(Path("static"))
    print(job.run_database_backup(read_db_path()))


if __name__ == "__main__":
    main()