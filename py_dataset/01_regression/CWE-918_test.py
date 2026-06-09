import requests

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/image/fetch")
def fetch_image():
    image_url = request.json.get(
        "url",
        "",
    )
    response = requests.get(
        image_url,
        timeout=5,
    )

    return {
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "size": len(
            response.content,
        ),
    }
