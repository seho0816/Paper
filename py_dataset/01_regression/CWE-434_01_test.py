from flask import request


def upload_avatar():
    avatar = request.files["avatar"]

    if avatar.content_type.startswith("image/"):
        avatar.save(
            "./static/uploads/" + avatar.filename
        )
        return "avatar uploaded"

    return "invalid file", 400
