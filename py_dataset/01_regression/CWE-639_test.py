from flask import Flask, jsonify, request

app = Flask(__name__)

documents = {
    "doc-101": {
        "owner_id": "user-a",
        "title": "salary contract",
    },
    "doc-102": {
        "owner_id": "user-b",
        "title": "medical receipt",
    },
}


@app.get("/api/documents/<document_id>")
def read_document(document_id: str):
    current_user_id = request.headers.get(
        "X-User-Id",
        "",
    )
    document = documents[document_id]

    return jsonify({
        "requested_by": current_user_id,
        "document": document,
    })
