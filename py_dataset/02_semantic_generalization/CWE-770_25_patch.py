from urllib.parse import quote

import requests


# Define a maximum resource size to prevent memory exhaustion (CWE-770).
# This value should be determined based on application requirements and expected resource sizes.
# For example, 5 MB is a common sensible default for many web resources.
MAX_RESOURCE_SIZE_BYTES = 5 * 1024 * 1024  # 5 Megabytes


RESOURCE_ORIGIN = (
    "https://assets.example.com"
)


def download_resource(
    resource_name: str,
) -> bytes:
    if not resource_name.isidentifier():
        raise ValueError(
            "invalid resource name"
        )

    resource_url = (
        RESOURCE_ORIGIN
        + "/resources/"
        + quote(
            resource_name,
            safe="",
        )
    )
    
    # Use stream=True to prevent loading potentially very large files into memory all at once.
    # This is critical for mitigating CWE-770 by allowing chunked processing and size limits.
    with requests.get(
        resource_url,
        timeout=30,
        allow_redirects=False,
        stream=True,  # Enable streaming to control memory usage
    ) as response:
        response.raise_for_status()

        # Check 'Content-Length' header for an early exit if the resource is too large.
        # This header can be missing or spoofed, so a streaming limit is also required for robustness.
        content_length_header = response.headers.get('Content-Length')
        if content_length_header:
            try:
                declared_size = int(content_length_header)
                if declared_size > MAX_RESOURCE_SIZE_BYTES:
                    # Raise a ValueError if the declared size exceeds the limit, preventing full download.
                    raise ValueError(
                        f"Resource too large: {declared_size} bytes exceeds maximum of {MAX_RESOURCE_SIZE_BYTES} bytes."
                    )
            except ValueError:
                # If 'Content-Length' is not a valid integer, proceed with streaming and byte-count.
                pass

        # Read content in chunks, enforcing MAX_RESOURCE_SIZE_BYTES during download.
        # This protects against large responses even if 'Content-Length' is missing or incorrect.
        downloaded_size = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=8192):  # Iterate in 8KB chunks
            if chunk:  # Filter out keep-alive new chunks
                downloaded_size += len(chunk)
                if downloaded_size > MAX_RESOURCE_SIZE_BYTES:
                    # Raise a ValueError if the actual downloaded size exceeds the limit during streaming.
                    raise ValueError(
                        f"Resource content exceeded maximum size during download: {MAX_RESOURCE_SIZE_BYTES} bytes."
                    )
                chunks.append(chunk)
        
        # Concatenate all collected chunks into a single bytes object and return.
        # This happens only if the total size is within MAX_RESOURCE_SIZE_BYTES,
        # thereby preventing memory exhaustion (CWE-770).
        return b"".join(chunks)
