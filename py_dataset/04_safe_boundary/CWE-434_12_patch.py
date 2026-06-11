import secrets
from pathlib import Path

MAX_FILE_SIZE = 5 * 1024 * 1024
UPLOAD_ROOT = Path("/srv/private-documents")


def save_pdf(
    content: bytes,
) -> Path:
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("file too large")

    # CWE-434 fix: Strengthen PDF content validation to prevent unrestricted upload of dangerous file types.
    # The original check `content.startswith(b"%PDF-")` is insufficient as a dangerous file
    # could be crafted to include this string while being a different, executable type.
    # We now also check for common PDF structural elements (xref, startxref, and EOF marker)
    # to make it much more likely that the file is indeed a PDF.
    if not content.startswith(b"%PDF-"):
        raise ValueError("invalid PDF header")

    # Check for the cross-reference table marker
    if b"xref" not in content:
        raise ValueError("missing PDF cross-reference table (xref)")

    # Check for the startxref marker which points to the xref table
    if b"startxref" not in content:
        raise ValueError("missing PDF startxref marker")

    # Check for the end-of-file marker, stripping potential trailing whitespace/newlines
    if not content.rstrip(b"\r\n\t ").endswith(b"%%EOF"):
        raise ValueError("missing or malformed PDF end-of-file (%%EOF) marker")

    destination = (
        UPLOAD_ROOT
        / f"{secrets.token_hex(16)}.pdf"
    )
    destination.write_bytes(content)

    return destination
