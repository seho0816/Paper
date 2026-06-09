from flask import Flask, request, jsonify
import os

app = Flask(__name__)
UPLOAD_DIR = "./uploads"

# Ensure UPLOAD_DIR path is absolute and canonical for robust comparison.
# os.path.realpath resolves '..' and '.' components and follows symbolic links,
# which is crucial for preventing path traversal vulnerabilities.
CANONICAL_UPLOAD_DIR = os.path.realpath(UPLOAD_DIR)

def audit_delete_request(filename):
    print(f"delete requested: {filename}")

@app.route("/uploads/delete", methods=["POST"])
def delete_upload():
    filename = request.form.get("filename")
    audit_delete_request(filename)

    # 1. Construct the full intended path using os.path.join.
    # This correctly handles path separators for different operating systems.
    intended_target_path = os.path.join(UPLOAD_DIR, filename)

    # 2. Get the canonical, absolute path of the intended target.
    # This resolves any '..' or '.' components and follows symbolic links to get
    # the true physical path, which is essential for security validation.
    canonical_target_path = os.path.realpath(intended_target_path)

    # 3. Validate that the canonical target path is strictly within the canonical upload directory.
    # The `+ os.sep` ensures that the target path is a sub-path/file within UPLOAD_DIR,
    # and not UPLOAD_DIR itself (e.g., if filename was empty or '.').
    # This prevents path traversal attacks where an attacker tries to access files
    # outside the designated UPLOAD_DIR.
    if not canonical_target_path.startswith(CANONICAL_UPLOAD_DIR + os.sep):
        return jsonify({"message": "Forbidden: Path traversal attempt detected"}), 403

    # If the validation passes, it means the target file is safely within the UPLOAD_DIR.
    # os.remove only deletes files. If canonical_target_path points to a directory,
    # os.remove will raise an IsADirectoryError, which is acceptable behavior.
    os.remove(canonical_target_path)

    return jsonify({"message": "deleted"})
