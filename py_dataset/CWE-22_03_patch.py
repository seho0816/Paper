import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

# Define a safe base directory for downloads.
# All files served must reside within this directory.
# In a real application, this path should be securely configured,
# e.g., via environment variables or a dedicated config file.
DOWNLOAD_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')

def has_download_permission(user_id, file_path):
    return bool(user_id) and bool(file_path)

@app.route("/download")
def download_file():
    user_id = request.args.get("user_id")
    file_path = request.args.get("path") # This is the raw user-provided path

    if not has_download_permission(user_id, file_path):
        abort(403)

    # --- CWE-22 Fix Starts Here ---
    # 1. Construct the full intended path by joining the base download directory
    #    with the user-provided relative file_path.
    #    This step itself does not normalize '..' or absolute paths yet.
    potential_full_path = os.path.join(DOWNLOAD_DIRECTORY, file_path)

    # 2. Normalize both the base directory and the potential full path
    #    to resolve '..' components, '.' components, and absolute paths.
    abs_download_directory = os.path.abspath(DOWNLOAD_DIRECTORY)
    abs_potential_full_path = os.path.abspath(potential_full_path)

    # 3. Critical security check: Verify that the normalized potential file path
    #    actually starts with the normalized base download directory path.
    #    If it does not, it means the user-provided 'file_path' attempted to
    #    traverse outside the allowed directory.
    if not abs_potential_full_path.startswith(abs_download_directory):
        abort(403) # Path traversal attempt detected

    # 4. Further validation: Ensure the final resolved path points to an actual file.
    #    This prevents serving directories or non-existent paths, which could
    #    lead to information disclosure or errors.
    if not os.path.isfile(abs_potential_full_path):
        abort(404) # File not found or not a regular file

    # Use the verified and sanitized absolute path for sending the file.
    return send_file(abs_potential_full_path, as_attachment=True)
    # --- CWE-22 Fix Ends Here ---
