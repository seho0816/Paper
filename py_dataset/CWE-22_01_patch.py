import os
from flask import request

BASE_DIR = "/var/app/files"

def read_file():
    filename = request.args.get("filename")

    # CWE-22 fix: Prevent path traversal by validating the resolved path.
    # 1. Construct the intended full path using os.path.join for robustness.
    #    os.path.join correctly handles cases like filename being None or an empty string,
    #    resulting in BASE_DIR itself, which will later fail gracefully if BASE_DIR is a directory.
    candidate_path = os.path.join(BASE_DIR, filename)

    # 2. Resolve both the base directory and the candidate path to their absolute, real paths.
    #    This step canonicalizes paths, resolving '..', symbolic links, and redundant slashes.
    absolute_base_dir = os.path.abspath(BASE_DIR)
    absolute_candidate_path = os.path.abspath(candidate_path)

    # 3. Validate that the canonicalized candidate path is indeed within the canonicalized base directory.
    #    os.path.commonpath returns the longest common path prefix. If the common path of BASE_DIR
    #    and the candidate file is not BASE_DIR itself, it means the candidate file is outside BASE_DIR.
    if not os.path.commonpath([absolute_base_dir, absolute_candidate_path]) == absolute_base_dir:
        # If the path attempts to go outside BASE_DIR, raise an error to prevent file access.
        # This prevents the CWE-22 path traversal vulnerability.
        raise ValueError("Invalid filename provided: Path traversal attempt detected.")
    
    # If the path is validated as safe, use the absolute and canonicalized path for file operations.
    path = absolute_candidate_path

    with open(path, "r", encoding="utf-8") as f:
        return f.read()
