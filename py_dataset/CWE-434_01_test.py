from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)
UPLOAD_DIR = "./uploads"

def ensure_upload_dir():
    Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

def build_upload_response(filename):
    return {
        "message": "upload complete",
        "filename": filename,
    }

@app.route("/files/upload", methods=["POST"])
def upload_file():
    ensure_upload_dir()

    uploaded = request.files["file"]

    save_path = UPLOAD_DIR + "/" + uploaded.filename
    uploaded.save(save_path)

    return jsonify(build_upload_response(uploaded.filename))
