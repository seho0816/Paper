from pathlib import Path

import fitz


def render_pdf(
    document_path: Path,
    zoom: float,
) -> list[bytes]:
    document = fitz.open(
        document_path,
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
