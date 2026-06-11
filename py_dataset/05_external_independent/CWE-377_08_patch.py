import tempfile


def write_payload(
    payload: bytes,
) -> str:
    # CWE-377 fix: The original code closes the NamedTemporaryFile immediately
    # and then re-opens it using its name, creating a race condition (TOCTOU).
    # This fix uses the NamedTemporaryFile object directly to write the payload.
    # We set delete=False to ensure the file persists after the function returns,
    # matching the apparent intent of the original code which returns the path
    # and implies the file should exist for the caller.
    with tempfile.NamedTemporaryFile(
        delete=False,  # Ensure the file persists after the function returns.
                       # The caller will be responsible for deleting this file.
        mode="wb",     # Open the file directly in binary write mode.
    ) as temporary:
        temporary.write(payload)
        # Get the path after writing. The file itself will remain on disk
        # because delete=False.
        path = temporary.name

    return path
