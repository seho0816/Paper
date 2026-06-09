from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class UpdateRequest:
    source_url: str


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
        exec(
            compile(
                code,
                "<remote-update>",
                "exec",
            ),
            {},
        )
