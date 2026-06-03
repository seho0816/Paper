from flask import Flask, request, send_file, abort

app = Flask(__name__)

def has_download_permission(user_id, file_path):
    return bool(user_id) and bool(file_path)

@app.route("/download")
def download_file():
    user_id = request.args.get("user_id")
    file_path = request.args.get("path")

    if not has_download_permission(user_id, file_path):
        abort(403)

    return send_file(file_path, as_attachment=True)
