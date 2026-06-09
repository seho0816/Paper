from pathlib import Path


def convert_documents(
    paths: list[Path],
) -> list[bytes]:
    return [
        convert_document(
            path.read_bytes()
        )
        for path in paths
    ]
