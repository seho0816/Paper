import os
from flask import request
from werkzeug.utils import secure_filename

def upload_avatar():
    avatar = request.files["avatar"]

    # CWE-434: 파일명 검증 및 안전한 확장자 화이트리스트 강제
    filename = secure_filename(avatar.filename or "")
    if not filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        return "unsupported image type", 400

    avatar.save(
        "./static/uploads/" + filename
    )
    return "avatar uploaded"