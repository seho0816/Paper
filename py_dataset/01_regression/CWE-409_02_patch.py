import bz2


# Define a reasonable maximum decompressed size to prevent decompression bombs.
# For example, 50 megabytes. This value should be tuned based on application
# requirements and expected backup sizes.
MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB


def decode_backup(
    compressed_data: bytes,
) -> bytes:
    decompressor = bz2.BZ2Decompressor()
    decompressed_buffer = bytearray()
    total_decompressed_size = 0
    # Define a chunk size for both feeding input and extracting output
    OUTPUT_CHUNK_SIZE = 65536  # 64 KB

    input_offset = 0
    while True:
        # Determine how much of the compressed data to feed in this iteration.
        # If all compressed data has been fed, chunk_to_feed will be b''.
        chunk_to_feed = b''
        if input_offset < len(compressed_data):
            chunk_to_feed = compressed_data[input_offset : input_offset + OUTPUT_CHUNK_SIZE]
            input_offset += len(chunk_to_feed)

        try:
            # Decompress a chunk, limiting the output size for each iteration.
            # This helps prevent sudden large memory allocations for output.
            decompressed_chunk = decompressor.decompress(chunk_to_feed, max_length=OUTPUT_CHUNK_SIZE)
        except bz2.BZ2Error as e:
            # Handle corrupted or invalid compressed data gracefully
            raise ValueError("Invalid BZ2 compressed data") from e

        if decompressed_chunk:
            decompressed_buffer.extend(decompressed_chunk)
            total_decompressed_size += len(decompressed_chunk)

            # Check for decompression bomb: if total decompressed size exceeds the limit
            if total_decompressed_size > MAX_DECOMPRESSED_SIZE:
                raise ValueError(
                    f"Decompressed data size ({total_decompressed_size} bytes) exceeds "
                    f"limit ({MAX_DECOMPRESSED_SIZE} bytes)"
                )

        # Termination condition for the loop:
        # 1. All compressed data has been fed (`input_offset >= len(compressed_data)`).
        # 2. The decompressor has reached the end of the BZ2 stream (`decompressor.eof` is True).
        # 3. No more decompressed output is currently available (`decompressed_chunk` is b'').
        if input_offset >= len(compressed_data) and decompressor.eof and not decompressed_chunk:
            break

        # Additional check for incomplete stream or internal error:
        # If all compressed data has been fed, but the decompressor has not reached EOF
        # and it also isn't producing any more output (e.g., stuck or incomplete data).
        if input_offset >= len(compressed_data) and not decompressor.eof and not decompressed_chunk:
            raise ValueError("Incomplete BZ2 compressed data stream")

    # Flush any remaining internal buffers from the decompressor to ensure all data is extracted
    # and to catch potential errors from incomplete streams that only manifest at flush.
    try:
        final_flush_chunk = decompressor.flush()
        if final_flush_chunk:
            decompressed_buffer.extend(final_flush_chunk)
            total_decompressed_size += len(final_flush_chunk)
            if total_decompressed_size > MAX_DECOMPRESSED_SIZE:
                 raise ValueError(
                    f"Decompressed data size ({total_decompressed_size} bytes) exceeds "
                    f"limit ({MAX_DECOMPRESSED_SIZE} bytes) during final flush"
                )
    except bz2.BZ2Error as e:
        raise ValueError("Invalid BZ2 compressed data (error during final flush)") from e

    return bytes(decompressed_buffer)
