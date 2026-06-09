import zipfile
from flask import request

UPLOAD_DIR = "/var/app/uploads"

def extract_zip():
    archive = request.files["archive"]
    archive.save("/tmp/upload.zip")

    with zipfile.ZipFile("/tmp/upload.zip") as zf:
        for member in zf.namelist():
            zf.extract(member, UPLOAD_DIR)

    return "extracted"
