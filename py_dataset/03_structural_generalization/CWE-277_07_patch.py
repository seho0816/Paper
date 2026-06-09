import asyncio
import os
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
        # CWE-277: Ensure secure permissions for the created directory.
        # 0o700 means read, write, execute for owner only.
        await asyncio.to_thread(
            target.parent.mkdir,
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        await asyncio.to_thread(
            target.write_bytes,
            body,
        )
        # CWE-277: Ensure secure permissions for the created file.
        # Path.write_bytes does not accept a mode argument for creation.
        # Explicitly set permissions after writing using os.chmod.
        # 0o600 means read, write for owner only.
        await asyncio.to_thread(
            os.chmod,
            target,
            0o600,
        )
        return target
