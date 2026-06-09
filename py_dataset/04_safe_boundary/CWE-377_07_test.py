import tempfile
from pathlib import Path


def process_document(
    content: bytes,
) -> bytes:
    with tempfile.TemporaryDirectory(
        prefix="document_",
    ) as directory:
        source = (
            Path(directory)
            / "source.bin"
        )
        source.write_bytes(
            content
        )

        return transform_document(
            source
        )
