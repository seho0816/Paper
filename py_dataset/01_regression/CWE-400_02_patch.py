import io
from flask import request, abort


def upload_file():
    # Define a maximum allowed file size to prevent Uncontrolled Resource Consumption (CWE-400).
    # For example, 10 MB limit. This prevents an attacker from uploading arbitrarily large files
    # that would exhaust server memory when calling .read().
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    # Access the uploaded file storage object.
    # The original code implicitly assumes the "file" key exists in request.files.
    uploaded_file = request.files["file"]

    # Read the file content in chunks to control memory usage and enforce the size limit.
    file_bytes_buffer = io.BytesIO()
    total_size = 0
    chunk_size = 4096  # Read in 4KB chunks to efficiently handle the stream

    while True:
        chunk = uploaded_file.stream.read(chunk_size)
        if not chunk:
            # End of file stream
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_SIZE:
            # If the file exceeds the defined maximum size, abort the request.
            # This directly addresses CWE-400 by preventing excessive resource consumption.
            abort(413, description=f"File is too large. Maximum allowed size is {MAX_FILE_SIZE / (1024*1024):.0f} MB.")
        file_bytes_buffer.write(chunk)

    # After successfully reading the file within the size limit,
    # retrieve the complete content from the buffer.
    file_bytes_buffer.seek(0)  # Reset the buffer's position to the beginning
    content = file_bytes_buffer.read()

    # Call the original content processing function with the now safely sized content.
    process_uploaded_content(
        content,
    )

    return {
        "size": len(content),
    }
