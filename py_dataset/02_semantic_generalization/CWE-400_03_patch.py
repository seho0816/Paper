from pathlib import Path

import fitz


def render_pdf(
    document_path: Path,
    zoom: float,
) -> list[bytes]:
    # CWE-400: Limit the zoom factor to prevent uncontrolled resource consumption.
    # An excessively large zoom value can lead to extremely large image dimensions,
    # causing out-of-memory errors or high CPU usage during rendering.
    MAX_ALLOWED_ZOOM = 10.0
    if zoom > MAX_ALLOWED_ZOOM:
        zoom = MAX_ALLOWED_ZOOM

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
