import lzma
import os


# Define a reasonable maximum size for decompressed data.
# This value should be determined based on application requirements and available memory.
# It can be configured via an environment variable for flexibility.
# Default to 100 MB if the environment variable is not set.
MAX_LZMA_DECOMPRESSION_SIZE_BYTES = int(os.environ.get("MAX_LZMA_DECOMPRESSION_SIZE_BYTES", 100 * 1024 * 1024))


def import_payload(
    compressed_payload: bytes,
) -> bytes:
    try:
        raw_payload = lzma.decompress(
            compressed_payload
        )
    except lzma.LZMAError as e:
        # Handle cases where the compressed data is malformed or corrupt.
        # This prevents potential denial of service from malformed input.
        raise ValueError("Invalid LZMA compressed data provided") from e
    except MemoryError as e:
        # Catch MemoryError explicitly if decompression itself exhausts memory.
        # This is a direct mitigation for the decompression bomb (CWE-409).
        raise ValueError(f"Decompression bomb detected: Memory allocation failed during decompression") from e

    # After successful decompression, check if the resulting payload is excessively large.
    # This prevents processing of payloads that, while successfully decompressed,
    # could still lead to resource exhaustion in subsequent steps (CWE-409).
    if len(raw_payload) > MAX_LZMA_DECOMPRESSION_SIZE_BYTES:
        raise ValueError(f"Decompressed payload size ({len(raw_payload)} bytes) exceeds maximum allowed size ({MAX_LZMA_DECOMPRESSION_SIZE_BYTES} bytes). Possible decompression bomb.")

    return raw_payload
