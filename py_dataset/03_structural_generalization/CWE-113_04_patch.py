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
        # CWE-113 fix: Remove carriage return (CR) and line feed (LF) characters
        # from the filename to prevent HTTP Response Splitting.
        sanitized_filename = response.filename.replace('\r', '').replace('\n', '')
        return {
            "Content-Disposition": (
                "attachment; filename="
                + sanitized_filename
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
