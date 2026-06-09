from flask import Flask, request, jsonify
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "./uploads"

# CWE-434 fix: Define a set of allowed extensions for uploaded files.
# This prevents attackers from uploading dangerous file types (e.g., scripts, executables).
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}

def ensure_upload_dir():
    Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

def build_upload_response(filename):
    return {
        "message": "upload complete",
        "filename": filename,
    }

# CWE-434 fix: Helper function to check if the uploaded file's extension is allowed.
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/files/upload", methods=["POST"])
def upload_file():
    ensure_upload_dir()

    # The original code would raise a KeyError if 'file' is not in request.files.
    # To maintain the existing behavior and not add new error handling features,
    # we proceed assuming 'file' will be present as per original code structure.
    uploaded = request.files["file"]

    # If the user submits an empty part without a filename, handle it.
    if uploaded.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # CWE-434 fix: Validate the file extension and sanitize the filename.
    if uploaded and allowed_file(uploaded.filename):
        # CWE-434 fix: Sanitize the filename to prevent path traversal attacks
        # and other issues caused by malicious filenames.
        filename = secure_filename(uploaded.filename)
        
        # Use pathlib.Path for safe and platform-independent path construction.
        save_path = Path(UPLOAD_DIR) / filename
        uploaded.save(save_path)
        
        return jsonify(build_upload_response(filename))
    else:
        # CWE-434 fix: Return an error if the file type is not allowed.
        return jsonify({"error": "File type not allowed"}), 400
