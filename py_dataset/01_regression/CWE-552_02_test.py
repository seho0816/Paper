from pathlib import Path
import tarfile


def archive_logs(log_directory: str) -> str:
    output = Path("media") / "exports" / "logs.tar.gz"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        archive.add(log_directory, arcname="logs")
    return str(output)
