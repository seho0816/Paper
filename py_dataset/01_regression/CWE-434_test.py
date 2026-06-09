from flask import request


def upload():
    uploaded = request.files["file"]
    uploaded.save(
        "uploads/" + uploaded.filename
    )

    return "uploaded"
