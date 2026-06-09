from flask import Flask, request

app = Flask(__name__)

UPLOAD_DIR = "./uploads"

@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded_file = request.files["file"]

    save_path = f"{UPLOAD_DIR}/{uploaded_file.filename}"
    uploaded_file.save(save_path)

    return "uploaded"