from flask import Flask, request
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "./uploads"

# CWE-434 Fix: Define a set of allowed file extensions.
# Customize this list based on the specific requirements of your application.
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """
    CWE-434 Fix: Helper function to check if the uploaded file has an allowed extension.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload_file():
    # CWE-434 Fix: Ensure a file part exists in the request
    if 'file' not in request.files:
        return "No file part", 400
    
    uploaded_file = request.files["file"]

    # CWE-434 Fix: Ensure a filename was provided (i.e., user selected a file)
    if uploaded_file.filename == '':
        return "No selected file", 400

    # CWE-434 Fix: Validate the file extension and ensure the file object is valid
    if uploaded_file and allowed_file(uploaded_file.filename):
        # CWE-434 Fix: Sanitize the filename to prevent directory traversal attacks
        # and ensure a safe filename for saving on the server.
        filename = secure_filename(uploaded_file.filename)
        
        # Ensure the upload directory exists. This is good practice.
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # CWE-434 Fix: Construct the save path using os.path.join for platform independence
        # and to correctly handle the sanitized filename.
        save_path = os.path.join(UPLOAD_DIR, filename)
        uploaded_file.save(save_path)

        return "uploaded"
    else:
        # CWE-434 Fix: Return an error if the file type is not allowed
        return "Invalid file type", 400
