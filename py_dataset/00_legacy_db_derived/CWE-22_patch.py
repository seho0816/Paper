import os
from flask import request, send_file, abort

def logo():
    img = request.args.get('image_name')

    # Define the intended base directory for images.
    # The original code uses os.getcwd(), so we maintain that behavior.
    base_dir = os.getcwd()

    if not img:
        # Handle cases where 'image_name' parameter is missing.
        # A 400 Bad Request is appropriate here.
        abort(400)

    # Construct the full path based on the base directory and user input.
    # This step alone is not safe against path traversal.
    requested_path = os.path.join(base_dir, img)

    # Get the absolute and normalized path for both the base directory and the requested path.
    # This resolves '..' and other path ambiguities.
    abs_base_dir = os.path.abspath(base_dir)
    abs_requested_path = os.path.abspath(requested_path)

    # CRITICAL SECURITY CHECK:
    # Ensure that the absolute requested path actually starts with the absolute base directory.
    # If it does not, it means the user input attempted to access a file outside the
    # designated base directory (path traversal).
    if not abs_requested_path.startswith(abs_base_dir):
        # Deny access if path traversal is detected.
        # Returning 404 Not Found is a common practice to avoid leaking information
        # about the server's file structure.
        abort(404)

    # If the path is validated as safe and within the allowed directory,
    # proceed to send the file using the verified absolute path.
    return send_file(abs_requested_path)
