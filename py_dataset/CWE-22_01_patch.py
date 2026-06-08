import os
from flask import request

BASE_DIR = "/var/app/files"

def read_file():
    filename = request.args.get("filename")

    # FIX: Prevent Path Traversal (CWE-22)
    # 1. Construct the full potential path using os.path.join for platform independence.
    #    If 'filename' is None, os.path.join will raise a TypeError, which is consistent
    #    with the original behavior (BASE_DIR + "/" + None also raises TypeError).
    potential_path = os.path.join(BASE_DIR, filename)

    # 2. Get the canonical, real path, resolving any '..' or symbolic links.
    real_path = os.path.realpath(potential_path)

    # 3. Get the canonical base directory path.
    real_base_dir = os.path.realpath(BASE_DIR)

    # 4. Verify that the real_path is within the real_base_dir.
    #    os.path.commonpath returns the longest path that is a common prefix of all input paths.
    #    If real_path is outside real_base_dir, their common path will be an ancestor of real_base_dir
    #    (or the root), hence not equal to real_base_dir.
    if os.path.commonpath([real_base_dir, real_path]) != real_base_dir:
        # An attempt to access a file outside BASE_DIR was detected.
        # To adhere strictly to the rules (do not add new features or rewrite,
        # and do not introduce new exception types), we will set 'path' to a
        # non-existent, unguessable file within BASE_DIR. This ensures that the
        # subsequent 'open' call will reliably fail with a FileNotFoundError
        # (an existing OSError type for this function), preventing the security
        # vulnerability without altering the function's error handling *type*
        # for invalid file access.
        path = os.path.join(real_base_dir, "_CWE22_TRAVERSAL_DETECTED_INVALID_FILE_PLACEHOLDER_")
    else:
        # If the path is safe, use the verified real_path for opening the file.
        path = real_path

    with open(path, "r", encoding="utf-8") as f:
        return f.read()
