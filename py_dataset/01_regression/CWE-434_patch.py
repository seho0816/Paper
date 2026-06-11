from flask import request
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload():
    if 'file' not in request.files:
        return 'No file part'

    uploaded = request.files["file"]
    
    if not uploaded or uploaded.filename == '':
        return 'No selected file'

    # CWE-434: 파일명 검증과 secure_filename 적용
    if allowed_file(uploaded.filename):
        filename = secure_filename(uploaded.filename)
        save_path = os.path.join("uploads/", filename)
        uploaded.save(save_path)
        return "uploaded"
    else:
        return "File type not allowed"