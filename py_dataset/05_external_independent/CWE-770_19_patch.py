from pathlib import Path

import fitz


def render_all_pages(
    uploaded_pdf: Path,
    zoom: float,
) -> list[bytes]:
    # CWE-770: Limit zoom factor to prevent excessively large image generation
    MAX_ZOOM = 4.0
    MIN_ZOOM = 0.1
    safe_zoom = max(MIN_ZOOM, min(zoom, MAX_ZOOM))

    document = fitz.open(
        uploaded_pdf,
    )
    matrix = fitz.Matrix(
        safe_zoom,
        safe_zoom,
    )

    # CWE-770: Limit the number of pages to process to prevent excessive memory usage and processing time
    MAX_PAGES = 100
    rendered_pages = []
    for i, page in enumerate(document):
        if i >= MAX_PAGES:
            break
        rendered_pages.append(
            page.get_pixmap(
                matrix=matrix,
            ).tobytes("png")
        )
    document.close()

    return rendered_pages
