from pathlib import Path
import os
import asyncio

from aiohttp import web


# Define a safe, controlled directory for backups.
# Using Path(os.getcwd()) ensures an absolute path relative to where the script is run.
# This anchors all backups to a specific, application-controlled directory,
# preventing path traversal vulnerabilities.
SAFE_BACKUP_BASE_DIR = Path(os.getcwd()) / "backups"


async def build_backup():
    """Simulates an asynchronous backup process, returning dummy content.
    This function was not provided in the original snippet but was called,
    so a dummy implementation is included for completeness."""
    await asyncio.sleep(0.01)
    return b"This is the secure backup content."


async def create_backup(
    request: web.Request,
) -> web.Response:
    payload = await request.json()

    # Ensure the safe backup directory exists.
    # 'parents=True' creates any necessary parent directories.
    # 'exist_ok=True' prevents an error if the directory already exists.
    SAFE_BACKUP_BASE_DIR.mkdir(parents=True, exist_ok=True)

    # CWE-73 fix: External Control of File Name or Path.
    # Instead of directly using the user's full path input, we sanitize it.
    # Path(str(payload["destination"])).name extracts only the base filename,
    # stripping any directory components (e.g., 'foo/../bar.txt' becomes 'bar.txt').
    # This prevents path traversal attacks like writing to arbitrary locations
    # outside the SAFE_BACKUP_BASE_DIR.
    user_provided_filename = Path(str(payload["destination"])).name

    # Construct the final secure path by joining the safe base directory
    # with the sanitized filename. This guarantees the file is written
    # within the designated backup directory.
    destination = SAFE_BACKUP_BASE_DIR / user_provided_filename

    destination.write_bytes(
        await build_backup()
    )

    return web.json_response({
        "destination": str(destination),
    })


app = web.Application()
app.router.add_post(
    "/backup",
    create_backup,
)
