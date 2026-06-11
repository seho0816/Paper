from dataclasses import dataclass

from PIL import Image

# Define reasonable limits for resource allocation to prevent CWE-770 (Allocation of Resources Without Limits)
# These values should be chosen based on expected service usage and available server resources.
MAX_CANVAS_WIDTH = 2048  # Maximum allowed width in pixels
MAX_CANVAS_HEIGHT = 2048 # Maximum allowed height in pixels
MAX_CANVAS_COPIES = 10   # Maximum allowed number of copies

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
        # Validate input parameters to prevent excessive resource allocation (CWE-770)
        # Raising ValueError for invalid inputs protects against OOM and DoS.
        if not (0 < request.width <= MAX_CANVAS_WIDTH):
            raise ValueError(f"Width must be between 1 and {MAX_CANVAS_WIDTH} pixels.")
        if not (0 < request.height <= MAX_CANVAS_HEIGHT):
            raise ValueError(f"Height must be between 1 and {MAX_CANVAS_HEIGHT} pixels.")
        if not (0 < request.copies <= MAX_CANVAS_COPIES):
            raise ValueError(f"Number of copies must be between 1 and {MAX_CANVAS_COPIES}.")

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
