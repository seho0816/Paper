import yaml

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/config/import")
def import_config():
    uploaded = request.files[
        "config"
    ]
    content = uploaded.read().decode(
        "utf-8",
    )
    config = yaml.safe_load(
        content,
    )

    return {
        "keys": list(config),
    }
