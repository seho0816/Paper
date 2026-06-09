from pathlib import Path

import fitz


def render_all_pages(
    uploaded_pdf: Path,
    zoom: float,
) -> list[bytes]:
    document = fitz.open(
        uploaded_pdf,
    )
    matrix = fitz.Matrix(
        zoom,
        zoom,
    )

    return [
        page.get_pixmap(
            matrix=matrix,
        ).tobytes("png")
        for page in document
    ]
