import gzip
from io import BytesIO

import pandas as pd


def load_uploaded_frame(
    compressed_csv: bytes,
) -> pd.DataFrame:
    # CWE-409: Improper Handling of Highly Compressed Data (Data Bomb)
    # To prevent a decompression bomb (e.g., gzip bomb), we decompress the data
    # in a controlled manner and impose a maximum limit on its decompressed size.
    # This value (100 MB) should be adjusted based on the expected legitimate
    # maximum size of your compressed CSV files.
    MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB

    decompressed_buffer = BytesIO()
    current_decompressed_size = 0

    # Decompress the gzip data chunk by chunk and monitor the size.
    # If 'compressed_csv' is not a valid gzip file, gzip.GzipFile will raise
    # an OSError (e.g., "Not a gzipped file") or BadGzipFile, which is an
    # appropriate response to malformed input.
    with gzip.GzipFile(fileobj=BytesIO(compressed_csv), mode='rb') as gz_file:
        while True:
            chunk = gz_file.read(4096)  # Read in 4KB chunks
            if not chunk:
                break
            current_decompressed_size += len(chunk)
            if current_decompressed_size > MAX_DECOMPRESSED_SIZE:
                # Raise an error if the decompressed size exceeds the limit,
                # preventing excessive memory consumption and potential DoS.
                raise ValueError(
                    f"Decompressed data size exceeds the maximum allowed limit "
                    f"({MAX_DECOMPRESSED_SIZE / (1024*1024):.0f} MB)."
                )
            decompressed_buffer.write(chunk)

    # Rewind the buffer to the beginning so pandas can read its content.
    decompressed_buffer.seek(0)

    # Pass the pre-decompressed buffer to pandas.read_csv.
    # The 'compression' argument is no longer needed because the data has
    # already been decompressed safely.
    return pd.read_csv(
        decompressed_buffer,
    )
