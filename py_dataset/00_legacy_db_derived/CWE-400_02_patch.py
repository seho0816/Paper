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
    MAX_ITEMS_PER_REQUEST = 1000

    raw_body = request.get_data()
    
    try:
        items = json.loads(raw_body)
    except json.JSONDecodeError:
        return jsonify({"message": "Invalid JSON format"}, 400)

    if not isinstance(items, list):
        return jsonify({"message": "Expected a JSON array of items"}, 400)
    
    if len(items) > MAX_ITEMS_PER_REQUEST:
        return jsonify({"message": f"Too many items. Maximum allowed is {MAX_ITEMS_PER_REQUEST}."}, 413)

    results = []
    for item in items:
        results.append(process_item(item))

    return jsonify({
        "count": len(results),
        "message": "imported",
    })
