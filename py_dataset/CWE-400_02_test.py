from flask import Flask, request, jsonify
import json

app = Flask(__name__)

def process_item(item):
    return {
        "status": "processed",
        "item": item,
    }

@app.route("/items/import", methods=["POST"])
def import_items():
    raw_body = request.get_data()
    items = json.loads(raw_body)

    results = []
    for item in items:
        results.append(process_item(item))

    return jsonify({
        "count": len(results),
        "message": "imported",
    })
