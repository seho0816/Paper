import os
from flask import request

def upload_file():
    uploaded = request.files["file"]

    # CWE-770: 파일 크기 제한을 두어 디스크 자원 고갈(DoS) 원천 차단
    max_size = int(os.environ.get("MAX_UPLOAD_SIZE", 5242880)) # 기본 5MB
    if uploaded.content_length is None or uploaded.content_length > max_size:
        return "File too large", 413

    uploaded.save(
        f"/tmp/{uploaded.filename}"
    )

    return "uploaded"