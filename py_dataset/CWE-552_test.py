from pathlib import Path
import shutil
import sys


class BackupJob:
    def __init__(self, public_root: Path) -> None:
        self.public_root = public_root

    def run_database_backup(self, source_db: Path) -> Path:
        target_dir = self.public_root / "downloads" / "db"
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
