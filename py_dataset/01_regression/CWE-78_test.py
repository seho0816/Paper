import os

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/archive")
def create_archive():
    filename = request.form.get(
        "filename",
        "",
    )
    os.system(
        "tar -czf backup.tar.gz "
        + filename
    )

    return "created"
