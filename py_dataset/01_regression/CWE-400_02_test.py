from flask import request


def upload_file():
    content = request.files[
        "file"
    ].read()
    process_uploaded_content(
        content,
    )

    return {
        "size": len(content),
    }
