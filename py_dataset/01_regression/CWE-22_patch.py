import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

DOWNLOAD_ROOT = "/srv/downloads"


@app.get("/api/files/download")
def download_file():
    filename = request.args.get("filename", "")
    
    # Construct the full intended path by joining the download root with the provided filename.
    # os.path.join handles path separators correctly across different operating systems
    # and prevents basic bypasses where filename might start with a '/' or contain redundant slashes.
    potential_file_path = os.path.join(DOWNLOAD_ROOT, filename)
    
    # Normalize the path to resolve any '..' (parent directory) or '.' (current directory)
    # components and obtain the absolute path. This is the core step for mitigating CWE-22
    # Path Traversal vulnerabilities.
    normalized_file_path = os.path.abspath(potential_file_path)
    
    # Get the normalized absolute path of the designated download root.
    # This provides a canonical reference point for comparison.
    normalized_download_root = os.path.abspath(DOWNLOAD_ROOT)
    
    # Verify that the `normalized_file_path` is strictly within or is the `DOWNLOAD_ROOT`.
    # This check ensures that an attacker cannot use path traversal sequences (e.g., "../../../")
    # to access files outside the allowed `DOWNLOAD_ROOT` directory.
    # 1. `normalized_file_path.startswith(normalized_download_root + os.sep)`:
    #    Ensures the path is a file or subdirectory *within* the `DOWNLOAD_ROOT`.
    #    Appending `os.sep` prevents issues where a path like `/srv/downloadsomething`
    #    might erroneously match `/srv/downloads`.
    # 2. `normalized_file_path == normalized_download_root`:
    #    Allows the `DOWNLOAD_ROOT` itself to be requested, for instance, if `filename` is empty.
    #    The subsequent `os.path.isfile` check will then correctly handle whether this is a file.
    if not (normalized_file_path.startswith(normalized_download_root + os.sep) or
            normalized_file_path == normalized_download_root):
        # If the path attempts to access resources outside the `DOWNLOAD_ROOT`, it's a
        # path traversal attempt, and access should be forbidden.
        abort(403) # Forbidden
        
    # Ensure that the resolved path points to an actual file.
    # This prevents serving directory listings (if the web server configuration allows)
    # or attempting to serve non-existent paths, enhancing robustness and security.
    if not os.path.isfile(normalized_file_path):
        abort(404) # Not Found (or 403 Forbidden, depending on specific security policy)

    return send_file(
        normalized_file_path,
        as_attachment=True,
    )
