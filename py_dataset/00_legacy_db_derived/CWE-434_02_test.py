from flask import Flask, request, jsonify

app = Flask(__name__)

def is_image_by_header(uploaded_file):
    return uploaded_file.content_type.startswith("image/")

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    avatar = request.files["avatar"]

    if is_image_by_header(avatar):
        save_path = "./static/uploads/" + avatar.filename
        avatar.save(save_path)

        return jsonify({
            "message": "avatar uploaded",
            "path": save_path,
        })

    return jsonify({"message": "invalid file"}), 400
