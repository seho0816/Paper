from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MediaRender:
    client_output_path: str
    payload: bytes


class MediaRenderService:
    def persist(
        self,
        render: MediaRender,
    ) -> str:
        path = Path(
            render.client_output_path
        )
        path.write_bytes(
            render.payload
        )

        return str(path)
