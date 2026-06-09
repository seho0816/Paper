from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)

DOCUMENT_ROOT = Path(
    "/srv/documents",
).resolve()


@app.get("/api/documents/content")
def read_document():
    requested_name = request.args.get(
        "name",
        "",
    )
    target = (
        DOCUMENT_ROOT
        / requested_name
    ).resolve()

    if not target.is_relative_to(
        DOCUMENT_ROOT,
    ):
        abort(400)

    if not target.is_file():
        abort(404)

    return target.read_text(
        encoding="utf-8",
    )
