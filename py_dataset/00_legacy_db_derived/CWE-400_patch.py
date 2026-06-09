from flask import Flask, request, abort
import os
import subprocess
import uuid

app = Flask(__name__)
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# [PATCH CWE-400] 리소스 할당 제한:
# 업로드 파일의 최대 크기를 500MB로 제한하여
# 공격자가 수십 GB 파일을 올려 서버 메모리/디스크를 고갈시키는 것을 방지.
MAX_CONTENT_LENGTH_MB = 500
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH_MB * 1024 * 1024

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        abort(400)

    uuid_file_name = f"{uuid.uuid4()}.mp4"
    file_path = os.path.join(UPLOAD_FOLDER, uuid_file_name)
    output_path = os.path.join(UPLOAD_FOLDER, f"{uuid_file_name}_720p.mp4")

    file.save(file_path)

    subprocess.run(
        ['ffmpeg', '-i', file_path, '-vf', 'scale=1280:720', output_path],
        check=True
    )

    return "File uploaded and processed!"