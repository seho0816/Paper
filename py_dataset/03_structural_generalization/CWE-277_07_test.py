import asyncio
from pathlib import Path


class AsyncCredentialSnapshotService:
    def __init__(
        self,
        shared_root: Path,
    ) -> None:
        self._shared_root = shared_root

    async def save(
        self,
        account_id: str,
        body: bytes,
    ) -> Path:
        target = (
            self._shared_root
            / 'credential-snapshots'
            / f'{account_id}.bin'
        )
        await asyncio.to_thread(
            target.parent.mkdir,
            parents=True,
            exist_ok=True,
        )
        await asyncio.to_thread(
            target.write_bytes,
            body,
        )
        return target
