import gzip
import json
import io


def decode_event_batch(
    compressed_body: bytes,
) -> list[dict]:
    # CWE-409: Resource Exhaustion (Denial-of-Service) due to uncontrolled
    # decompression size. A small compressed_body could decompress into an
    # extremely large raw_body, consuming excessive memory and leading to a DoS.
    #
    # Fix: Implement a hard limit on the maximum size of the decompressed data.
    # If the decompressed data exceeds this limit, an error is raised,
    # preventing resource exhaustion.
    MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # Example limit: 10 MB

    decompressed_data_buffer = io.BytesIO()
    total_decompressed_bytes = 0

    # Use gzip.GzipFile with io.BytesIO to decompress data in chunks.
    # This allows monitoring the decompressed size in real-time.
    # Other potential decompression errors (e.g., BadGzipFile, EOFError)
    # will naturally propagate from gzip.GzipFile as they would from gzip.decompress.
    with gzip.GzipFile(fileobj=io.BytesIO(compressed_body), mode='rb') as gzipped_file:
        while True:
            chunk = gzipped_file.read(4096)  # Read in 4KB chunks
            if not chunk:
                break
            
            # Check if adding the current chunk would exceed the maximum allowed size.
            if total_decompressed_bytes + len(chunk) > MAX_DECOMPRESSED_SIZE:
                raise ValueError(
                    f"Decompressed data size exceeds limit of {MAX_DECOMPRESSED_SIZE} bytes. "
                    "Possible resource exhaustion attempt."
                )
            
            decompressed_data_buffer.write(chunk)
            total_decompressed_bytes += len(chunk)

    raw_body = decompressed_data_buffer.getvalue()

    return json.loads(
        raw_body.decode(
            "utf-8"
        )
    )
