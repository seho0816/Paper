import gzip
from pathlib import Path


def read_compressed_report(
    report_path: Path,
) -> bytes:
    MAX_DECOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB
    CHUNK_SIZE = 4096

    decompressed_data = bytearray()
    total_decompressed_bytes = 0

    with gzip.open(
        report_path,
        "rb",
    ) as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            
            total_decompressed_bytes += len(chunk)
            if total_decompressed_bytes > MAX_DECOMPRESSED_SIZE:
                raise ValueError(
                    f"Decompressed data from '{report_path}' exceeds maximum allowed size "
                    f"({MAX_DECOMPRESSED_SIZE / (1024*1024):.0f} MB)."
                )
            
            decompressed_data.extend(chunk)
            
    return bytes(decompressed_data)
