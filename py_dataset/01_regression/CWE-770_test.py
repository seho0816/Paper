from flask import request


def upload_file():
    uploaded = request.files["file"]
    uploaded.save(
        f"/tmp/{uploaded.filename}"
    )

    return "uploaded"
