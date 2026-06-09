from flask import Flask, request, jsonify
import os

app = Flask(__name__)
UPLOAD_DIR = "./uploads"

def audit_delete_request(filename):
    print(f"delete requested: {filename}")

@app.route("/uploads/delete", methods=["POST"])
def delete_upload():
    filename = request.form.get("filename")
    audit_delete_request(filename)

    target = UPLOAD_DIR + "/" + filename
    os.remove(target)

    return jsonify({"message": "deleted"})
