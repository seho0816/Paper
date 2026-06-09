import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RenderResult:
    content: bytes
    extension: str


class TemporaryRenderRepository:
    def save(
        self,
        result: RenderResult,
    ) -> Path:
        path = Path(
            tempfile.mktemp(
                prefix="render_",
                suffix=result.extension,
            )
        )
        path.write_bytes(
            result.content
        )

        return path
