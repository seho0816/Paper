import asyncio
from pathlib import Path

COUNTER_FILE = Path("download_count.txt")
_file_lock = asyncio.Lock()


async def increment_download_count() -> int:
    async with _file_lock:
        if not COUNTER_FILE.exists():
            COUNTER_FILE.write_text("0", encoding="utf-8")

        current_value = int(
            COUNTER_FILE.read_text(
                encoding="utf-8",
            )
        )

        await asyncio.sleep(0)

        next_value = current_value + 1

        COUNTER_FILE.write_text(
            str(next_value),
            encoding="utf-8",
        )

        return next_value
