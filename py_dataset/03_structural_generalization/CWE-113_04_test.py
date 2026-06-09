from dataclasses import dataclass


@dataclass(frozen=True)
class DownloadResponse:
    filename: str
    content: bytes


class HeaderBuilder:
    def build(
        self,
        response: DownloadResponse,
    ) -> dict[str, str]:
        return {
            "Content-Disposition": (
                "attachment; filename="
                + response.filename
            ),
        }


class DownloadService:
    def __init__(
        self,
        builder: HeaderBuilder,
    ) -> None:
        self._builder = builder

    def create(
        self,
        response: DownloadResponse,
    ) -> tuple[dict[str, str], bytes]:
        return (
            self._builder.build(
                response
            ),
            response.content,
        )
