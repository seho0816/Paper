from fastapi import Request, HTTPException
from starlette import status


# Assume decode_large_blob is defined elsewhere and its implementation is not part of this fix.
# For the purpose of this example, we assume it takes bytes and returns some decodable object.
# def decode_large_blob(content: bytes):
#     # Placeholder for the actual decoding logic
#     return content # Example: simply return the content itself


MAX_BODY_SIZE = 10 * 1024 * 1024  # Define a maximum allowed request body size (e.g., 10 MB)


async def import_blob(
    request: Request,
) -> int:
    total_size = 0
    body_chunks = []

    # Read the request body in chunks to prevent unbounded memory allocation (CWE-770).
    # This prevents a Denial of Service attack by limiting the size of the incoming data.
    async for chunk in request.stream():
        total_size += len(chunk)
        if total_size > MAX_BODY_SIZE:
            # If the body exceeds the defined limit, stop processing and raise an error.
            # HTTP 413 Payload Too Large is the appropriate status code.
            raise HTTPException(
                status_code=status.HTTP_413_PAYLOAD_TOO_LARGE,
                detail=f"Request body too large. Maximum allowed size is {MAX_BODY_SIZE} bytes."
            )
        body_chunks.append(chunk)

    # Reassemble the chunks into a single bytes object after validating the size.
    content = b"".join(body_chunks)

    # The original decoding logic is maintained, now operating on size-limited content.
    parsed = decode_large_blob(content)

    return len(parsed)
