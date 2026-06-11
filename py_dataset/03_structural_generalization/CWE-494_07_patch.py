import hashlib
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class UpdateRequest:
    source_url: str
    expected_hash: str


class UpdateDownloader:
    def download(
        self,
        request: UpdateRequest,
    ) -> bytes:
        response = requests.get(
            request.source_url,
            timeout=10,
        )
        response.raise_for_status()

        return response.content


class UpdateService:
    def __init__(
        self,
        downloader: UpdateDownloader,
    ) -> None:
        self._downloader = downloader

    def apply(
        self,
        request: UpdateRequest,
    ) -> None:
        code = self._downloader.download(
            request
        )

        calculated_hash = hashlib.sha256(code).hexdigest()

        if calculated_hash != request.expected_hash:
            raise ValueError("Code integrity check failed: downloaded content hash does not match expected hash.")

        exec(
            compile(
                code,
                "<remote-update>",
                "exec",
            ),
            {},
        )
