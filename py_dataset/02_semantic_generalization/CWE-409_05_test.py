import gzip
from pathlib import Path


def read_compressed_report(
    report_path: Path,
) -> bytes:
    with gzip.open(
        report_path,
        "rb",
    ) as source:
        return source.read()
