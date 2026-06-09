from flask import Flask, request, jsonify
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# CWE-434 Fix: Define a whitelist of allowed image extensions.
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def is_image_by_header(uploaded_file):
    # CWE-434 Fix: Do not rely solely on client-provided content_type.
    # Add server-side validation for the file's extension.

    # 1. Check content type (original check, now a secondary validation layer)
    is_header_image = uploaded_file.content_type.startswith("image/")

    # 2. Check file extension against a whitelist (primary CWE-434 mitigation)
    # Get the original filename to extract its extension for validation.
    filename = uploaded_file.filename
    if not filename:
        return False

    # Extract extension. os.path.splitext is a robust way to do this.
    _, ext = os.path.splitext(filename)
    # Remove leading dot and convert to lowercase for case-insensitive comparison.
    ext = ext[1:].lower() if ext else ''

    is_extension_allowed = ext in ALLOWED_EXTENSIONS

    # Both conditions (header and whitelisted extension) must be true
    # for the file to be considered a safe image type.
    return is_header_image and is_extension_allowed

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    avatar = request.files["avatar"]

    # Handle cases where no file was selected or filename is empty
    if not avatar.filename:
        return jsonify({"message": "no selected file"}), 400

    # Validate the file using the enhanced function that checks both header and extension.
    if is_image_by_header(avatar):
        # CWE-434 Fix: Sanitize the filename to prevent directory traversal
        # and other filename-based attacks (e.g., `../../../etc/passwd`).
        filename_secure = secure_filename(avatar.filename)
        
        # Use os.path.join for secure path construction, avoiding path traversal issues.
        save_path = os.path.join("./static/uploads/", filename_secure)
        
        avatar.save(save_path)

        return jsonify({
            "message": "avatar uploaded",
            "path": save_path,
        })

    return jsonify({"message": "invalid file"}), 400
