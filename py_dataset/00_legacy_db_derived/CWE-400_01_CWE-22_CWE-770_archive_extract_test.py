import zipfile
from flask import Flask, request, jsonify

app = Flask(__name__)

def save_archive_to_temp(archive):
    temp_path = "/tmp/archive.zip"
    archive.save(temp_path)
    return temp_path

@app.route("/archive/upload", methods=["POST"])
def upload_archive():
    archive = request.files["archive"]
    archive_path = save_archive_to_temp(archive)

    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall("/tmp/extracted")

    return jsonify({"message": "done"})
