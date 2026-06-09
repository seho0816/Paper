from flask import Flask, request, send_file

app = Flask(__name__)

DOWNLOAD_ROOT = "/srv/downloads"


@app.get("/api/files/download")
def download_file():
    filename = request.args.get("filename", "")
    file_path = DOWNLOAD_ROOT + "/" + filename

    return send_file(
        file_path,
        as_attachment=True,
    )
