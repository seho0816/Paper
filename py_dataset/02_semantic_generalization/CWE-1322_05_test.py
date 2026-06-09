from pathlib import Path

async def read_generated_archive(archive_path: Path) -> bytes:
    return archive_path.read_bytes()
