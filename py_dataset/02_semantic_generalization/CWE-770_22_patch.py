import fitz

MAX_PAGES_TO_RENDER = 50
MAX_ALLOWED_ZOOM = 4.0
MAX_FILE_SIZE = 10 * 1024 * 1024  # 최대 10MB 제한

def render_uploaded_pdf(
    uploaded_pdf: bytes,
    zoom: float,
) -> list[bytes]:
    # CWE-770: 들어오는 원본 파일의 메모리 크기 자체를 통제
    if len(uploaded_pdf) > MAX_FILE_SIZE:
        raise ValueError("PDF file size exceeds maximum allowed limit.")

    if not (0.1 <= zoom <= MAX_ALLOWED_ZOOM):
        raise ValueError(f"Zoom factor must be between 0.1 and {MAX_ALLOWED_ZOOM}.")

    matrix = fitz.Matrix(zoom, zoom)

    with fitz.open(stream=uploaded_pdf, filetype="pdf") as document:
        if document.page_count > MAX_PAGES_TO_RENDER:
            raise ValueError(f"PDF exceeds maximum allowed pages ({MAX_PAGES_TO_RENDER}).")

        return [
            page.get_pixmap(matrix=matrix).tobytes("png")
            for page in document
        ]