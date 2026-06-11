from pathlib import Path

MAX_UPLOAD_SIZE = 10 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def save_stream(
    source,
    destination: Path,
) -> int:
    total = 0

    with destination.open("wb") as output:
        while True:
            # Calculate the maximum number of additional bytes allowed to be written.
            # This ensures that we don't attempt to read more data than the overall limit permits,
            # preventing temporary excessive memory allocations for the chunk buffer
            # if CHUNK_SIZE were to be larger than MAX_UPLOAD_SIZE or the remaining limit.
            remaining_limit = MAX_UPLOAD_SIZE - total

            # If no more bytes are allowed to be written (either we've hit the limit exactly
            # or `total` has already somehow exceeded it).
            # This correctly handles the case where total reaches exactly MAX_UPLOAD_SIZE,
            # ensuring no further reads or writes occur.
            if remaining_limit <= 0:
                break

            # Determine the actual number of bytes to read in this iteration.
            # It must not exceed the defined CHUNK_SIZE, nor the overall remaining limit.
            bytes_to_read = min(CHUNK_SIZE, remaining_limit)

            chunk = source.read(bytes_to_read)

            if not chunk:  # End of stream
                break

            current_chunk_len = len(chunk)

            # Defensive check: Although `bytes_to_read` limits the request size,
            # if `source.read` implementation is buggy and returns more than requested,
            # or if `remaining_limit` was somehow miscalculated, this catches it.
            # This ensures that the total written bytes never exceed MAX_UPLOAD_SIZE.
            if total + current_chunk_len > MAX_UPLOAD_SIZE:
                raise ValueError("upload too large")

            output.write(chunk)
            total += current_chunk_len

    return total
