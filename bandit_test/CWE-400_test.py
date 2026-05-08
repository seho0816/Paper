from flask import Flask, request
import os
import subprocess
import uuid  # Import UUID library

app = Flask(__name__)
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    uuid_file_name = f"{uuid.uuid4()}.mp4"  # Generate a random UUID as the filename
    file_path = os.path.join(UPLOAD_FOLDER, uuid_file_name)
    output_path = os.path.join(UPLOAD_FOLDER, f"{uuid_file_name}_720p.mp4")

    # Save the uploaded file
    file.save(file_path)

    # Safely invoke FFmpeg
    subprocess.run(['ffmpeg', '-i', file_path, '-vf', 'scale=1280:720', output_path], check=True)

    return "File uploaded and processed!"