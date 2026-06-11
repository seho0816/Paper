import requests

MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # Define a maximum allowed download size (e.g., 10 MB)


def download_resource(
    resource_url: str,
) -> bytes:
    # Use stream=True to prevent loading the entire content into memory immediately
    # and to allow checking content size during download.
    response = requests.get(
        resource_url,
        timeout=30,
        stream=True,
    )
    response.raise_for_status()

    # Check Content-Length header if available to preemptively reject overly large files.
    content_length = response.headers.get('Content-Length')
    if content_length:
        try:
            content_length = int(content_length)
            if content_length > MAX_DOWNLOAD_SIZE:
                response.close()  # Close the connection immediately to save resources
                raise ValueError(
                    f"Remote resource size ({content_length} bytes) exceeds maximum allowed size "
                    f"of {MAX_DOWNLOAD_SIZE} bytes."
                )
        except ValueError:
            # If Content-Length is malformed, proceed with streaming check
            pass

    downloaded_bytes = b""
    current_size = 0

    # Iterate over content in chunks to monitor total downloaded size
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:  # Filter out keep-alive new chunks
            current_size += len(chunk)
            if current_size > MAX_DOWNLOAD_SIZE:
                response.close()  # Close the connection to stop further download
                raise ValueError(
                    f"Downloaded content exceeded maximum allowed size of {MAX_DOWNLOAD_SIZE} bytes."
                )
            downloaded_bytes += chunk

    return downloaded_bytes
