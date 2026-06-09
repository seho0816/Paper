import fitz


def render_uploaded_pdf(
    uploaded_pdf: bytes,
    zoom: float,
) -> list[bytes]:
    matrix = fitz.Matrix(
        zoom,
        zoom,
    )

    with fitz.open(
        stream=uploaded_pdf,
        filetype="pdf",
    ) as document:
        return [
            page.get_pixmap(
                matrix=matrix,
            ).tobytes(
                "png"
            )
            for page in document
        ]
