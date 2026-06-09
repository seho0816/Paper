# 복합 CWE
from flask import Flask, request, jsonify
from pathlib import Path
import os

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads"

def ensure_upload_dir():
    Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

def save_uploaded_file(uploaded):
    ensure_upload_dir()
    path = os.path.join(UPLOAD_DIR, uploaded.filename)
    uploaded.save(path)
    return path

@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]

    saved_path = save_uploaded_file(uploaded)
    os.chmod(saved_path, 0o777)

    return jsonify({
        "message": "saved",
        "path": saved_path,
    })
