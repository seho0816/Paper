from dataclasses import dataclass

from PIL import Image


@dataclass(frozen=True)
class CanvasRequest:
    width: int
    height: int
    copies: int


class CanvasService:
    def create(
        self,
        request: CanvasRequest,
    ) -> list[Image.Image]:
        return [
            Image.new(
                "RGBA",
                (
                    request.width,
                    request.height,
                ),
            )
            for _ in range(request.copies)
        ]
