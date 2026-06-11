from PIL import Image


def create_copies(
    source: Image.Image,
    requested_count: int,
) -> list[Image.Image]:
    return [
        source.copy()
        for _ in range(
            requested_count
        )
    ]
